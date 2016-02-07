// #![feature(clone_from_slice)]

extern crate hyper;
extern crate libc;
extern crate rustc_serialize;
extern crate uuid;

mod pwdb;

use std::io::{self, Write};
use std::error::Error;
use std::collections::{HashMap, BTreeMap};

use hyper::Server;
use hyper::server::Request;
use hyper::server::Response;
use hyper::server::Handler;
use hyper::header::ContentType;
use hyper::uri::RequestUri;
use hyper::method::Method;

use uuid::Uuid;

use rustc_serialize::json::{Json, ToJson};

// GET
// /dump
// arguments:
// password

// POST
// /add_record
// arguments:
// required: password, title
// optional: user, url

// returns new db state

struct DbHandler {
    dbpath: String,
}

// POST /blog/posts
// Accept: application/json
// Content-Type: application/json
// Content-Length: 57

// HTTP/1.1 201 Created
// Content-Type: application/json
// Content-Length: 65
// Connection: close

fn url_args(arg_str: &str) -> HashMap<String, String> {
    let raw_args: Vec<_> = arg_str.split('&').collect();
    let mut args = HashMap::new();
    for arg in raw_args {
        match arg.find('=') {
            Some(idx) => {
                let (param, val) = arg.split_at(idx);
                args.insert(param.to_string(), val[1..].to_string());
            }
            None => {
                println!("bad bad bad request");
            }
        }
    }
    args
}

enum MyError {
    MissingArg,
    NoResource,
}

// XXX need to do url decoding of these damn strings!
// XXX db is a shared resource - protect w/ mutex
impl Handler for DbHandler {
    fn handle(&self, req: Request, mut res: Response) {
        match req.uri {
            RequestUri::AbsolutePath(s) => {
                let (route, args) = match s.find('?') {
                    Some(idx) => (&s[0..idx], url_args(&s[idx+1..])),
                    None => (&s[..], HashMap::new()),
                };
                match (req.method, route) {
                    (Method::Get, "/dump") =>
                        match args.get("password") {
                            Some(pw) => {
                                self.write_json_response(
                                    res,
                                    self.dump(pw).as_bytes());
                            }
                            None => {
                                res.headers_mut().set(ContentType::json());
                                let mut res = res.start().unwrap();
                                res.write_all(make_resp(
                                    22,
                                    &"missing required argument".to_json())
                                              .as_bytes()).unwrap();
                            }
                        },
                    (Method::Post, "/add_record") =>
                        match (args.get("db_password"), args.get("title"), args.get("rec_password")) {
                            (None, _, _) | (_, None, _) | (_, _, None) =>
                                self.write_json_response(
                                    res,
                                    make_resp(22, &"missing required argument".to_json()).as_bytes()),
                            (Some(db_pass), Some(title), Some(rec_pass)) =>
                                self.write_json_response(
                                    res,
                                    self.add_record(db_pass, title, rec_pass).as_bytes()),
                        },
                    (Method::Delete, "/remove_record") =>
                        match (args.get("password"), args.get("uuid")) {
                            (None, _) | (_, None) =>
                                self.write_bad_request(res, MyError::MissingArg),

                            (Some(pass), Some(uuid)) =>
                                self.write_json_response(
                                    res,
                                    self.remove_record(pass, uuid).as_bytes()),
                        },
                    _ => self.write_bad_request(res, MyError::NoResource),
                }
            }
            RequestUri::AbsoluteUri(_) => println!("abs uri"),
            _ => println!("something else"),
        }
    }
}

fn make_resp<T: ToJson>(err_code: i32, res: &T) -> String {
    let mut d = BTreeMap::new();
    d.insert("err".to_string(), err_code.to_json());
    d.insert("res".to_string(), res.to_json());
    Json::Object(d).to_string()
}

fn last_err_response(e: io::Error) -> String {
    let err = match e.raw_os_error() {
        Some(0) | None => 22,
        Some(i) => i,
    };
    make_resp(err, &e.description().to_json())
}

impl DbHandler {
    fn new(dbpath: String) -> Self {
        DbHandler { dbpath: dbpath }
    }

    fn write_json_response(&self, mut res: Response, body: &[u8]) {
        res.headers_mut().set(ContentType::json());
        let mut res = res.start().unwrap();
        res.write_all(body).unwrap();
    }

    fn write_bad_request(&self, res: Response, myerr: MyError) {
        match myerr {
            MyError::MissingArg =>
                self.write_json_response(
                    res,
                    make_resp(22, &"missing required argument".to_json())
                        .as_bytes()),
            MyError::NoResource =>
                self.write_json_response(
                    res,
                    make_resp(2, &"no such resource".to_json())
                        .as_bytes()),
        }
    }

    fn dump(&self, pw: &str) -> String {
        match pwdb::Db::open(pw, &self.dbpath) {
            Ok(db) => {
                make_resp(0, &db)
            }
            Err(e) => {
                let err = match e.raw_os_error() {
                    Some(0) | None => 1,
                    Some(i) => i,
                };
                make_resp(err, &e.description().to_json())
            }
        }
    }

    fn add_record(&self, db_pass: &str, title: &str, password: &str) -> String {
        match pwdb::Db::open(db_pass, &self.dbpath) {
            Ok(mut db) => {
                if db.add_record(title, password, "", "").is_some() {
                    match db.save(db_pass, &self.dbpath) {
                        Ok(()) => make_resp(0, &db),
                        Err(e) => last_err_response(e),
                    }
                } else {
                    last_err_response(
                        io::Error::new(io::ErrorKind::Other,
                                       "couldn't add record"))
                }
            }
            Err(e) => last_err_response(e),
        }
    }

    fn remove_record(&self, pass: &str, uuid: &str) -> String {
        if let Ok(u) = Uuid::parse_str(uuid) {
            match pwdb::Db::open(pass, &self.dbpath) {
                Ok(mut db) => {
                    if db.remove_record(&u) {
                        match db.save(pass, &self.dbpath) {
                            Ok(()) => make_resp(0, &db),
                            Err(e) => last_err_response(e),
                        }
                    } else {
                        last_err_response(
                            io::Error::new(io::ErrorKind::Other,
                                           "no such record"))
                    }
                }
                Err(e) => last_err_response(e),
            }
        } else {
            last_err_response(
                io::Error::new(io::ErrorKind::Other,
                               "couldn't parse uuid"))
        }
    }
}

// https requires a cert and all that junk

// run with path to db
fn main() {
    let dbpath = "/Users/zach/Documents/pwsafe_foo";
    let hdlr = DbHandler::new(dbpath.to_string());
    Server::http("127.0.0.1:3000").unwrap().handle(hdlr).unwrap();
}

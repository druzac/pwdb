#![feature(clone_from_slice)]

extern crate hyper;
extern crate libc;
extern crate rustc_serialize;
extern crate uuid;

mod pwdb;

use std::io::Write;
use std::error::Error;
use std::collections::{HashMap, BTreeMap};

use hyper::Server;
use hyper::server::Request;
use hyper::server::Response;
use hyper::server::Handler;
use hyper::header::ContentType;
use hyper::uri::RequestUri;

use rustc_serialize::json::{Json, ToJson};

// GET
// /dump
// arguments:
// password

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

impl Handler for DbHandler {
    fn handle(&self, req: Request, mut res: Response) {
        match req.uri {
            RequestUri::AbsolutePath(s) => {
                let (route, args) = match s.find('?') {
                    Some(idx) => (&s[0..idx], url_args(&s[idx+1..])),
                    None => (&s[..], HashMap::new()),
                };
                match route {
                    "/dump" => {
                        match args.get("password") {
                            Some(pw) => {
                                res.headers_mut().set(ContentType::json());
                                let mut res = res.start().unwrap();
                                res.write_all(self.dump(pw).as_bytes()).unwrap();
                            }
                            None => {
                                res.headers_mut().set(ContentType::json());
                                let mut res = res.start().unwrap();
                                res.write_all(make_resp(
                                    22,
                                    &"missing required argument".to_json())
                                              .as_bytes()).unwrap();
                            }
                        }
                    }
                    _ => println!("something else tickled: {}", route),
                }
            },
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

impl DbHandler {
    fn new(dbpath: String) -> Self {
        DbHandler { dbpath: dbpath }
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
}

// https requires a cert and all that junk

// run with path to db
fn main() {
    let dbpath = "/Users/zach/Documents/pwsafe_foo";
    let hdlr = DbHandler::new(dbpath.to_string());
    Server::http("127.0.0.1:3000").unwrap().handle(hdlr).unwrap();
}

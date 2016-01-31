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

// analyze the request here
// fn hello(_: Request, res: Response) {
//     res.send(b"Hello World!").unwrap();
// }

struct DbHandler {
    dbpath: String,
}

// sample http junk

// POST /blog/posts
// Accept: application/json
// Content-Type: application/json
// Content-Length: 57

// HTTP/1.1 201 Created
// Content-Type: application/json
// Content-Length: 65
// Connection: close

// use std::io::Write;
// use hyper::header::ContentLength;
// fn handler(mut res: Response) {
//     let body = b"Hello World!";
//     res.headers_mut().set(ContentLength(body.len() as u64));
//     let mut res = res.start().unwrap();
//     res.write_all(body).unwrap();
// }

// get the path and the args in the uri

impl Handler for DbHandler {
    fn handle(&self, req: Request, mut res: Response) {
        // let body = b"hello, world!";
        println!("remote addr: {:?}, method: {:?}, uri: {:?}",
                 req.remote_addr,
                 req.method,
                 req.uri);
        match req.uri {
            RequestUri::AbsolutePath(s) => {
                // split the string into the path and the args
                let pieces: Vec<_> = s.split('?').collect();
                assert!(pieces.len() == 2 || pieces.len() == 1);
                let raw_args: Vec<_> = pieces[1].split('&').collect();
                // association list
                // let mut args = Vec::new();
                let mut args = HashMap::new();
                for arg in raw_args {
                    println!("arg: {:?}", arg);
                    match arg.find('=') {
                        Some(idx) => {
                            let (param, val) = arg.split_at(idx);
                            args.insert(param.to_string(), val[1..].to_string());
                        }
                        None => {
                            println!("bad bad bad request");
                            panic!();
                        }
                    }
                }
                println!("processed args: {:?}", args);
                match pieces[0] {
                    "/dump" => {
                        match args.get("password") {
                            Some(pw) => {
                                println!("have a password arg");
                                res.headers_mut().set(ContentType::json());
                                let mut res = res.start().unwrap();
                                res.write_all(self.dump(pw).as_bytes()).unwrap();
                            }
                            None => {
                                println!("no password!");
                            }
                        }
                    }
                    _ => println!("something else tickled: {}", pieces[0]),
                }
            },
            RequestUri::AbsoluteUri(_) => println!("abs uri"),
            _ => println!("something else"),
        }
        // res.headers_mut().set(ContentType::json());
        // let mut res = res.start().unwrap();
        // res.write_all(body).unwrap();
        // res.send(b"hello, world!").unwrap();
        // res.send(
    }
}

impl DbHandler {
    fn new(dbpath: String) -> Self {
        DbHandler { dbpath: dbpath }
    }

    fn dump(&self, pw: &str) -> String {
        let mut d = BTreeMap::new();
        match pwdb::Db::open(pw, &self.dbpath) {
            Ok(db) => {
                d.insert("err".to_string(), 0.to_json());
                d.insert("res".to_string(), db.to_json());
            }
            Err(e) => {
                let err = match e.raw_os_error() {
                    Some(0) | None => 1,
                    Some(i) => i,
                };
                d.insert("err".to_string(), err.to_json());
                d.insert("res".to_string(), e.description().to_json());
            }
        }
        Json::Object(d).to_string()
    }
}

// https requires a cert and all that junk

// run with path to db
fn main() {
    let dbpath = "/Users/zach/Documents/pwsafe_foo";
    let hdlr = DbHandler::new(dbpath.to_string());
    Server::http("127.0.0.1:3000").unwrap().handle(hdlr).unwrap();
}

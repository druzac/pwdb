use std::io::{Result, Error};
use std::ffi::{CString, CStr};
use std::collections::BTreeMap;

use libc::{c_short, c_char, c_uint};
use uuid::Uuid;
use rustc_serialize::json::{Json, ToJson};

#[derive(Debug)]
#[repr(C)]
struct CDb {
    header: CDbHeader,
    records: *mut CRecord,
}
#[derive(Debug)]
#[repr(C)]
struct CDbHeader {
    version: c_short,
    fields: *mut CField,
}

// uuid, password, and title are required
// everything else is optional
#[derive(Debug)]
#[repr(C)]
struct CRecord {
    uuid: [u8; 16],
    title: *mut c_char,
    password: *mut c_char,
    user: *mut c_char,
    url: *mut c_char,
    fields: *mut CField,
    next: *mut CRecord,
    prev: *mut CRecord,
}
#[derive(Debug)]
#[repr(C)]
struct CField {
    len: c_uint,
    ftype: c_char,
    data: *mut c_char,
    next: *mut CField,
    prev: *mut CField,
}

#[link(name = "pwdb")]
#[allow(dead_code)]
extern {
    fn pwsdb_open(pw: *const c_char, dbpath: *const c_char) -> *mut CDb;
    fn pwsdb_save(db: *const CDb, pw: *const c_char, dbpath: *const c_char);
    fn print_db(db: *const CDb);
    fn destroy_db(db: *mut CDb);
}

pub struct Db {
    cdb: *mut CDb,
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe {
            destroy_db(self.cdb);
        }
    }
}

#[allow(dead_code)]
impl Db {
    pub fn open(pw: &str, dbpath: &str) -> Result<Db> {
        let cdbp = CString::new(dbpath).unwrap();
        let cpw = CString::new(pw).unwrap();
        unsafe {
            let db = pwsdb_open(cpw.as_ptr(), cdbp.as_ptr());
            if db.is_null() {
                let err = Error::last_os_error();
                Err(err)
            } else {
                Ok(Db { cdb: db })
            }
        }
    }

    pub fn print(&self) {
        unsafe {
            print_db(self.cdb)
        }
    }
}



impl ToJson for Db {
    fn to_json(&self) -> Json {
        // let mut d = BTreeMap::new();
        let mut v = Vec::new();
        unsafe {
            let rec_head = (*self.cdb).records;
            let mut rec = rec_head;
            if !rec_head.is_null() {
                loop {
                    let mut recd = BTreeMap::new();
                    let pass = CStr::from_ptr((*rec).password);
                    let title = CStr::from_ptr((*rec).title);
                    let uuid = Uuid::from_bytes(&(*rec).uuid).unwrap();
                    recd.insert("password".to_string(),
                                pass.to_str().unwrap().to_json());
                    recd.insert("title".to_string(),
                                title.to_str().unwrap().to_json());
                    recd.insert("uuid".to_string(),
                                uuid.to_simple_string().to_json());
                    v.push(Json::Object(recd));
                    rec = (*rec).next;
                    if rec == rec_head {
                        break
                    }
                }
            }
        }
        Json::Array(v)
    }
}
// simplest representation:
// lists
// {records: [record]}
// record: { uuid: string, title: string, password: string}
// 

// need functions:
// rust repr <-> c repr

// void
// print_db(struct db *db);
// struct db *
// pwsdb_open(const char *pw, const char *dbpath);


// struct db *
// pwsdb_open(const char *pw, const char *dbpath);

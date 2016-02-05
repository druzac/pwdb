use std::io::{Result, Error};
use std::ffi::{CString, CStr};
use std::collections::BTreeMap;

use libc::{c_short, c_char, c_uint, c_int};
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
    fn pwsdb_save(db: *const CDb, pw: *const c_char, dbpath: *const c_char) -> c_int;
    fn print_db(db: *const CDb);
    fn destroy_db(db: *mut CDb);
    fn pwsdb_add_record(db: *mut CDb,
                        title: *const c_char,
                        pass: *const c_char,
                        user: *const c_char,
                        url: *const c_char,
                        uuid: *mut u8) // OUT
                        -> c_int;
    fn pwsdb_remove_record(db: *mut CDb, uuid: *const u8) -> c_int;
    fn pwsdb_get_pass(db: *const CDb, uuid: *const u8) -> *const c_char; // borrowed
}

pub struct Db {
    cdb: *mut CDb,
}

unsafe fn cstr_to_string(c_str: *const c_char) -> String {
    if c_str.is_null() {
        "".to_string()
    } else {
        match CStr::from_ptr(c_str).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => "".to_string(),
        }
    }
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

    pub fn add_record(&mut self,
                      title: &str,
                      pass: &str,
                      user: &str,
                      url: &str) -> Option<Uuid> {
        let mut raw_uuid: [u8; 16] = [0; 16];
        unsafe {
            let res = pwsdb_add_record(self.cdb,
                                       CString::new(title).unwrap().as_ptr(),
                                       CString::new(pass).unwrap().as_ptr(),
                                       CString::new(user).unwrap().as_ptr(),
                                       CString::new(url).unwrap().as_ptr(),
                                       raw_uuid.as_mut_ptr());
            match res {
                0 => Some(Uuid::from_bytes(&raw_uuid).unwrap()),
                _ => None,
            }
        }
    }

    pub fn remove_record(&mut self, uuid: &Uuid) -> bool {
        unsafe {
            let res = pwsdb_remove_record(self.cdb,
                                          uuid.as_bytes().as_ptr());
            match res {
                0 => true,
                _ => false,
            }
        }
    }

    pub fn save(&self, pw: &str, path: &str) -> Result<()> {
        unsafe {
            let rc = pwsdb_save(self.cdb,
                                CString::new(pw).unwrap().as_ptr(),
                                CString::new(path).unwrap().as_ptr());
            match rc {
                0 => Ok(()),
                _ => Err(Error::last_os_error()),
            }
        }
    }

    pub fn get_pass(&self, uuid: &Uuid) -> Option<String> {
        unsafe {
            let s = pwsdb_get_pass(self.cdb, uuid.as_bytes().as_ptr());
            if s.is_null() {
                None
            } else {
                Some(CStr::from_ptr(s).to_str().unwrap().to_string())
            }
        }
    }
}

impl ToJson for Db {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        fn header_to_json(hdr: &CDbHeader) -> Json {
            let mut blob = BTreeMap::new();
            blob.insert("version".to_string(),
                        hdr.version.to_json());
            Json::Object(blob)
        }

        unsafe fn record_to_json(rec: &CRecord) -> Json {
            let mut blob = BTreeMap::new();
            blob.insert("title".to_string(), cstr_to_string(rec.title).to_json());
            blob.insert("password".to_string(), cstr_to_string(rec.password).to_json());
            blob.insert("user".to_string(), cstr_to_string(rec.user).to_json());
            blob.insert("url".to_string(), cstr_to_string(rec.url).to_json());

            Json::Object(blob)
        }

        unsafe {
            d.insert("header".to_string(), header_to_json(&(*self.cdb).header));
            let rec_head = (*self.cdb).records;
            let mut rec = rec_head;
            let mut records = BTreeMap::new();
            if !rec_head.is_null() {
                loop {
                    let uuid = Uuid::from_bytes(&(*rec).uuid).unwrap();
                    records.insert(uuid.to_simple_string(),
                                   record_to_json(&*rec));
                    rec = (*rec).next;
                    if rec == rec_head {
                        break
                    }
                }
            }
            d.insert("records".to_string(), Json::Object(records));
            Json::Object(d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Db, CDb, CDbHeader};
    use std::ptr::null_mut;

    use std::path::PathBuf;
    use std::fs::create_dir_all;
    use std::env;
    use rustc_serialize::json::{Json, ToJson};

    fn new_cdb() -> CDb {
        CDb { header: CDbHeader { version: 0,
                                  fields: null_mut() },
              records: null_mut() }
    }

    #[test]
    fn write_db() {
        let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        println!("path is: {:?}", dir);
        let _ = create_dir_all(&dir);
        let fpath = dir.with_file_name("pwsdb_test");
        let mut cdb = new_cdb();
        let mut db = Db { cdb: &mut cdb };

        let uuid = db.add_record("title", "pass", "user", "url").unwrap();
        assert!(db.save("foo",
                        fpath.to_str().unwrap()).is_ok());
        let db = Db::open("foo", fpath.to_str().unwrap()).unwrap();
        let res = db.get_pass(&uuid);
        assert!(res.is_some());
        assert_eq!(res.unwrap(), "pass");
    }

    #[test]
    fn remove_record() {
        let mut cdb = new_cdb();
        let mut db = Db { cdb: &mut cdb };
        let u1 = db.add_record("t1", "p1", "u1", "url1").unwrap();
        let u2 = db.add_record("t2", "p2", "u2", "url2").unwrap();

        assert!(db.get_pass(&u1).is_some());
        assert!(db.get_pass(&u2).is_some());

        assert!(db.remove_record(&u2));
        assert!(db.get_pass(&u1).is_some());
        assert!(db.get_pass(&u2).is_none());
    }

    #[test]
    fn cdb_to_json() {
        let mut cdb = new_cdb();
        let mut db = Db { cdb: &mut cdb };
        let u1 = db.add_record("t1", "p1", "u1", "url1").unwrap();
        let mut jblob = db.to_json();
        if let Json::Object(ref mut base) = jblob {
            assert_eq!(base.len(), 2);
            let mut jrecords = base.remove("records").unwrap();
            if let Json::Object(ref mut records) = jrecords {
                assert_eq!(records.len(), 1);
                let mut jrec = records.remove(&u1.to_simple_string()).unwrap();
                if let Json::Object(ref mut rec) = jrec {
                    let jtitle = rec.remove("title").unwrap();
                    if let Json::String(ref title) = jtitle {
                        assert_eq!(title, "t1");
                    } else { assert!(false); }

                    let jpassword = rec.remove("password").unwrap();
                    if let Json::String(ref password) = jpassword {
                        assert_eq!(password, "p1");
                    } else { assert!(false); }

                    let juser = rec.remove("user").unwrap();
                    if let Json::String(ref user) = juser {
                        assert_eq!(user, "u1");
                    } else { assert!(false); }

                    let jurl = rec.remove("url").unwrap();
                    if let Json::String(ref url) = jurl {
                        assert_eq!(url, "url1");
                    } else { assert!(false); }

                } else { assert!(false); }
            } else { assert!(false); }
        } else { assert!(false); }
    }
}

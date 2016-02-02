use std::io::{Result, Error};
use std::ffi::{CString, CStr};
use std::collections::{HashMap, BTreeMap};
use std::slice;

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
}

#[derive(Debug)]
struct Record {
    title: String,
    password: String,
    user: String,
    url: String,
    fields: Vec<Field>,
}

#[derive(Debug)]
struct Field {
    ftype: u8,
    data: Vec<u8>,
}

struct DbHeader {
    version: u16,
    fields: Vec<Field>,
}

pub struct MyDb {
    header: DbHeader,
    records: HashMap<Uuid, Record>,
}

impl MyDb {
    pub fn new(version: u16) -> MyDb {
        MyDb {
            header: DbHeader { version: version,
                               fields: vec![] },
            records: HashMap::new()
        }
    }

    pub fn open(pw: &str, dbpath: &str) -> Result<MyDb> {
        let cdbp = CString::new(dbpath).unwrap();
        let cpw = CString::new(pw).unwrap();
        unsafe {
            let mut cdb = pwsdb_open(cpw.as_ptr(), cdbp.as_ptr());
            let is_null = cdb.is_null();
            if is_null {
                let err = Error::last_os_error();
                Err(err)
            } else {
                let res = Ok(cdb_to_db(cdb));
                res
            }
        }
    }
}

impl ToJson for Record {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("title".to_string(), self.title.to_json());
        d.insert("password".to_string(), self.password.to_json());
        d.insert("user".to_string(), self.user.to_json());
        d.insert("url".to_string(), self.url.to_json());
        Json::Object(d)
    }
}

impl ToJson for DbHeader {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("version".to_string(), self.version.to_json());
        Json::Object(d)
    }
}

impl ToJson for MyDb {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("header".to_string(), self.header.to_json());
        let mut records = BTreeMap::new();
        for (uuid, record) in self.records.iter() {
            records.insert(uuid.to_hyphenated_string(), record.to_json());
        }
        d.insert("records".to_string(), Json::Object(records));
        Json::Object(d)
    }
}

pub struct Db {
    cdb: *mut CDb,
}

unsafe fn cfield_to_fields(cfield: *const CField) -> Vec<Field> {
    let mut fs = vec![];
    let mut cf = cfield;
    if !cfield.is_null() {
        loop {
            let data = slice::from_raw_parts((*cf).data as *const u8,
                                             (*cf).len as usize);
            fs.push(Field { ftype: (*cf).ftype as u8, data: data.to_vec() } );
            cf = (*cf).next;
            if cf == cfield {
                break
            }
        }
    }
    fs
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

unsafe fn crecord_to_record(crec: *const CRecord) -> Record {
    Record {
        title: cstr_to_string((*crec).title),
        password: cstr_to_string((*crec).password),
        user: cstr_to_string((*crec).user),
        url: cstr_to_string((*crec).url),
        fields: cfield_to_fields((*crec).fields),
    }
}

unsafe fn records_map(crec_hd: *const CRecord) -> HashMap<Uuid, Record> {
    let mut records = HashMap::new();
    let mut crec = crec_hd;
    if !crec.is_null() {
        loop {
            let uuid = Uuid::from_bytes(&(*crec).uuid).unwrap();
            records.insert(uuid, crecord_to_record(crec));
            crec = (*crec).next;
            if crec == crec_hd {
                break
            }
        }
    }
    records
}

// needs the cdb to be non-null
// frees the memory
unsafe fn cdb_to_db(cdb: *mut CDb) -> MyDb {
    // build header
    let db_hdr = DbHeader {
        version: (*cdb).header.version as u16,
        fields: cfield_to_fields((*cdb).header.fields)
    };
    let res = MyDb {
        header: db_hdr,
        records: records_map((*cdb).records),
    };
    destroy_db(cdb);
    res
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

#[cfg(test)]
mod tests {
    use std::ffi::{CString, CStr};
    use uuid::Uuid;
    use libc::{c_char, c_int};
    use super::{CDb, MyDb, CDbHeader, cdb_to_db};
    use std::ptr::null_mut;
    use std::collections::HashMap;

    use std::path::PathBuf;
    use std::fs::{create_dir_all, File};
    use std::env;
    use rustc_serialize::json::{Json, ToJson};

    #[link(name = "pwdb")]
    extern {
        fn pwsdb_open(pw: *const c_char, dbpath: *const c_char) -> *mut CDb;
        fn pwsdb_save(db: *const CDb, pw: *const c_char, dbpath: *const c_char) -> c_int;
        fn print_db(db: *const CDb);
        fn destroy_db(db: *mut CDb);
        fn pwsdb_init(db: *mut CDb);
        fn pwsdb_add_record(db: *mut CDb,
                            title: *const c_char,
                            pass: *const c_char,
                            user: *const c_char,
                            url: *const c_char,
                            uuid: *mut u8);
    }

    fn new_cdb() -> CDb {
        CDb {
            header: CDbHeader {
                version: 0,
                fields: null_mut(),
            },
            records: null_mut(),
        }
    }

    #[test]
    fn it_works() {
        assert_eq!(4, 2 + 2);
    }

    #[test]
    fn empty_cdb_to_db() {
        let mut cdb = new_cdb();
        unsafe {
            let db = cdb_to_db(&mut cdb);
            assert_eq!(db.header.version, 0);
            assert!(db.header.fields.is_empty());
            assert!(db.records.is_empty());
        }
    }

    fn add_record_to_cdb(cdb: &mut CDb,
                         title: &str,
                         pass: &str,
                         user: &str,
                         url: &str) -> Uuid {
        let mut raw_uuid: [u8; 16] = [0; 16];
        unsafe {
            pwsdb_add_record(cdb,
                             CString::new(title).unwrap().as_ptr(),
                             CString::new(pass).unwrap().as_ptr(),
                             CString::new(user).unwrap().as_ptr(),
                             CString::new(url).unwrap().as_ptr(),
                             raw_uuid.first_mut().unwrap());
        }
        Uuid::from_bytes(&raw_uuid).unwrap()
    }

    #[test]
    fn write_db() {
        let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        println!("path is: {:?}", dir);
        let _ = create_dir_all(&dir);
        let fpath = dir.with_file_name("pwsdb_test");
        let mut cdb = new_cdb();
        let uuid = add_record_to_cdb(&mut cdb, "title", "pass", "user", "url");
        unsafe {
            assert_eq!(0,
                       pwsdb_save(&mut cdb,
                                  CString::new("foo").unwrap().as_ptr(),
                                  CString::new(fpath.to_str().unwrap()).unwrap().as_ptr()));
        }
        let mydb = MyDb::open("foo", fpath.to_str().unwrap()).unwrap();
        assert!(mydb.records.contains_key(&uuid));
        let blob = mydb.to_json();
        println!("res: {}", blob.to_string());
    }

    #[test]
    fn singleton_cdb_to_db() {
        let mut cdb = new_cdb();
        unsafe {
            pwsdb_init(&mut cdb);
            let exp_uuid = add_record_to_cdb(&mut cdb,
                                             "title",
                                             "pass",
                                             "user",
                                             "url");

            let db = cdb_to_db(&mut cdb);
            assert!(!db.records.is_empty());
            let (uuid, rec) = db.records.iter().next().unwrap();
            assert_eq!(uuid, &exp_uuid);
            assert_eq!(rec.title, "title");
            assert_eq!(rec.password, "pass");
            assert_eq!(rec.user, "user");
            assert_eq!(rec.url, "url");
        }
    }
}

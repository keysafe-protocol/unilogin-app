use mysql::*;
use mysql::prelude::*;

use std::fs::File;
use std::fs;

use glob::glob;
use std::io::Write;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub uname: String,
    pub uaddr: String,
    pub ukey: String
}

pub fn insert_user(pool: &Pool, user: User) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("insert into unilogin (uname, uaddr, ukey) values (?, ?, ?)",
        (user.uname, user.uaddr, user.ukey)).unwrap();
    tx.commit().unwrap();
}

pub fn query_user(pool: &Pool, stmt: String) -> Vec<User>{
    let mut conn = pool.get_conn().unwrap();
    let mut result: Vec<User> = Vec::new();
    conn.query_iter(stmt).unwrap().for_each(|row| {
        let r:(std::string::String, 
            std::string::String, 
            std::string::String) = from_row(row.unwrap());
        result.push(User {
            uname: r.0,
            uaddr: r.1,
            ukey: r.2,
        });
    });
    result
}

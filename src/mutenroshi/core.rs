pub mod auth;
pub mod conf;

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use crate::mutenroshi::db::{Database, Error};

#[derive(Clone)]
pub struct Context {
    pub dbro: Arc<Mutex<Database>>,
    pub session_secret: Vec<u8>,
    pub session_ttl_seconds: i64,
}

impl Context {
    pub fn open(
        path: impl AsRef<Path>,
        session_secret: Vec<u8>,
        session_ttl_seconds: i64,
    ) -> Result<Self, Error> {
        Ok(Self {
            dbro: Arc::new(Mutex::new(Database::open_ro(path)?)),
            session_secret,
            session_ttl_seconds,
        })
    }
}

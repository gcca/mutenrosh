use std::{
    error::Error as StdError,
    ffi::{CStr, CString, c_char, c_int},
    fmt,
    path::Path,
    ptr::{self, NonNull},
};

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_OPEN_READONLY: c_int = 0x0000_0001;
const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
const SQLITE_OPEN_URI: c_int = 0x0000_0040;
const SQLITE_OPEN_FULLMUTEX: c_int = 0x0001_0000;

#[repr(C)]
struct Sqlite3 {
    _private: [u8; 0],
}

#[repr(C)]
struct Sqlite3Statement {
    _private: [u8; 0],
}

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        database: *mut *mut Sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close_v2(database: *mut Sqlite3) -> c_int;
    fn sqlite3_errmsg(database: *mut Sqlite3) -> *const c_char;
    fn sqlite3_threadsafe() -> c_int;
    fn sqlite3_prepare_v2(
        database: *mut Sqlite3,
        sql: *const c_char,
        bytes: c_int,
        statement: *mut *mut Sqlite3Statement,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_bind_text(
        statement: *mut Sqlite3Statement,
        index: c_int,
        value: *const c_char,
        bytes: c_int,
        destructor: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    ) -> c_int;
    fn sqlite3_step(statement: *mut Sqlite3Statement) -> c_int;
    fn sqlite3_column_text(statement: *mut Sqlite3Statement, column: c_int) -> *const u8;
    fn sqlite3_column_bytes(statement: *mut Sqlite3Statement, column: c_int) -> c_int;
    fn sqlite3_finalize(statement: *mut Sqlite3Statement) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Open,
    Prepare,
    Bind,
    Step,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::Open => "open",
            Self::Prepare => "prepare",
            Self::Bind => "bind",
            Self::Step => "step",
        };

        write!(formatter, "SQLite {operation} failed")
    }
}

impl StdError for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    Row,
    Done,
}

pub struct Database {
    handle: Option<NonNull<Sqlite3>>,
}

impl Database {
    pub fn open_ro(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open(path.as_ref(), SQLITE_OPEN_READONLY)
    }

    pub fn open_rw(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open(path.as_ref(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
    }

    fn open(path: &Path, flags: c_int) -> Result<Self, Error> {
        if unsafe { sqlite3_threadsafe() } == 0 {
            return Err(Error::Open);
        }

        let path = path.to_str().ok_or(Error::Open)?;
        let path = CString::new(path).map_err(|_| Error::Open)?;
        let flags = if path.as_bytes().starts_with(b"file:") {
            flags | SQLITE_OPEN_URI
        } else {
            flags
        } | SQLITE_OPEN_FULLMUTEX;
        let mut raw_handle = ptr::null_mut();
        let code = unsafe { sqlite3_open_v2(path.as_ptr(), &mut raw_handle, flags, ptr::null()) };
        let handle = NonNull::new(raw_handle);

        if code != SQLITE_OK || handle.is_none() {
            if let Some(handle) = handle {
                unsafe {
                    let _ = sqlite3_close_v2(handle.as_ptr());
                }
            }
            return Err(Error::Open);
        }

        Ok(Self { handle })
    }

    pub fn close(&mut self) {
        let handle = self.handle.take().expect("closed a closed SQLite database");
        unsafe {
            let _ = sqlite3_close_v2(handle.as_ptr());
        }
    }

    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>, Error> {
        let sql = CString::new(sql).map_err(|_| Error::Prepare)?;
        let mut raw_handle = ptr::null_mut();
        let code = unsafe {
            sqlite3_prepare_v2(
                self.handle().as_ptr(),
                sql.as_ptr(),
                -1,
                &mut raw_handle,
                ptr::null_mut(),
            )
        };
        let handle = NonNull::new(raw_handle);

        if code != SQLITE_OK || handle.is_none() {
            return Err(Error::Prepare);
        }

        Ok(Statement {
            database: self,
            handle: handle.expect("checked SQLite statement handle"),
            bound_text: Vec::new(),
        })
    }

    pub fn error_message(&self) -> String {
        copy_c_string(unsafe { sqlite3_errmsg(self.handle().as_ptr()) })
    }

    fn handle(&self) -> NonNull<Sqlite3> {
        self.handle.expect("used a closed SQLite database")
    }
}

unsafe impl Send for Database {}

pub struct Statement<'database> {
    database: &'database Database,
    handle: NonNull<Sqlite3Statement>,
    bound_text: Vec<CString>,
}

impl Statement<'_> {
    pub fn bind_text(&mut self, index: c_int, value: &str) -> Result<(), Error> {
        let value = CString::new(value).map_err(|_| Error::Bind)?;
        self.bound_text.push(value);
        let value = self.bound_text.last().expect("stored bound SQLite text");
        let code =
            unsafe { sqlite3_bind_text(self.handle.as_ptr(), index, value.as_ptr(), -1, None) };

        if code == SQLITE_OK {
            Ok(())
        } else {
            Err(Error::Bind)
        }
    }

    pub fn step(&mut self) -> Result<Step, Error> {
        match unsafe { sqlite3_step(self.handle.as_ptr()) } {
            SQLITE_ROW => Ok(Step::Row),
            SQLITE_DONE => Ok(Step::Done),
            _ => Err(Error::Step),
        }
    }

    pub fn column_text(&self, column: c_int) -> String {
        let value = unsafe { sqlite3_column_text(self.handle.as_ptr(), column) };
        if value.is_null() {
            return String::new();
        }

        let bytes = unsafe { sqlite3_column_bytes(self.handle.as_ptr(), column) };
        if bytes <= 0 {
            return String::new();
        }

        let value = unsafe { std::slice::from_raw_parts(value, bytes as usize) };
        String::from_utf8_lossy(value).into_owned()
    }

    pub fn finalize(self) {
        unsafe {
            let _ = sqlite3_finalize(self.handle.as_ptr());
        }
    }

    pub fn error_message(&self) -> String {
        self.database.error_message()
    }
}

fn copy_c_string(value: *const c_char) -> String {
    if value.is_null() {
        return String::new();
    }

    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    const SHARED_DATABASE: &str = "file:mutenroshi-database-wrapper-test?mode=memory&cache=shared";
    static NEXT_SCRATCH_ID: AtomicU64 = AtomicU64::new(0);

    struct ScratchDatabase {
        directory: PathBuf,
        database: PathBuf,
    }

    impl ScratchDatabase {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before the Unix epoch")
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "mutenroshi-db-test-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("failed to create scratch directory");

            Self {
                database: directory.join("scratch.sqlite3"),
                directory,
            }
        }
    }

    impl Drop for ScratchDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.database);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[test]
    fn read_write_open_creates_a_database_and_database_is_send() {
        fn assert_send<T: Send>() {}

        let scratch = ScratchDatabase::new();
        let mut database = Database::open_rw(&scratch.database).expect("read-write open failed");

        assert_send::<Database>();
        assert!(scratch.database.exists());

        database.close();
    }

    #[test]
    fn shared_memory_supports_binding_stepping_and_owned_text() {
        let mut setup = Database::open_rw(SHARED_DATABASE).expect("read-write open failed");
        let mut create = setup
            .prepare("CREATE TABLE item (name TEXT PRIMARY KEY)")
            .expect("create prepare failed");
        assert_eq!(create.step(), Ok(Step::Done));
        create.finalize();

        let mut insert = setup
            .prepare("INSERT INTO item (name) VALUES (?1)")
            .expect("insert prepare failed");
        let name = "mutenroshi".to_owned();
        insert.bind_text(1, &name).expect("bind failed");
        drop(name);
        assert_eq!(insert.step(), Ok(Step::Done));
        insert.finalize();

        let mut reader = Database::open_ro(SHARED_DATABASE).expect("read-only open failed");
        let mut select = reader
            .prepare("SELECT name FROM item WHERE name = ?1")
            .expect("select prepare failed");
        select.bind_text(1, "mutenroshi").expect("bind failed");
        assert_eq!(select.step(), Ok(Step::Row));
        let name = select.column_text(0);
        assert_eq!(select.step(), Ok(Step::Done));
        assert_eq!(name, "mutenroshi");
        select.finalize();

        reader.close();
        setup.close();
    }

    #[test]
    fn read_only_open_fails_for_a_missing_database() {
        let scratch = ScratchDatabase::new();

        assert_eq!(
            Database::open_ro(&scratch.database).err(),
            Some(Error::Open)
        );
        assert!(!scratch.database.exists());
    }

    #[test]
    fn invalid_sql_fails_to_prepare_and_exposes_the_database_error() {
        let mut database = Database::open_rw(":memory:").expect("read-write open failed");

        assert_eq!(database.prepare("SELECT FROM").err(), Some(Error::Prepare));
        assert!(!database.error_message().is_empty());

        database.close();
    }
}

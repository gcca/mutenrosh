use crate::mutenroshi::{core::Context, db::Step};

#[derive(Debug, Eq, PartialEq)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

pub struct AuthRepository {
    context: Context,
}

impl AuthRepository {
    pub fn new(context: Context) -> Self {
        Self { context }
    }

    pub fn user_by(&self, username: &str) -> Option<AuthUser> {
        let database = match self.context.dbro.lock() {
            Ok(database) => database,
            Err(_) => {
                eprintln!("authentication user lookup failed: the database lock is poisoned");
                return None;
            }
        };
        let mut statement = match database
            .prepare("SELECT username, password FROM auth_user WHERE username = ?1")
        {
            Ok(statement) => statement,
            Err(_) => {
                eprintln!(
                    "authentication user lookup failed: {}",
                    database.error_message()
                );
                return None;
            }
        };
        let result: Result<Option<AuthUser>, String> = (|| {
            statement
                .bind_text(1, username)
                .map_err(|_| statement.error_message())?;

            match statement.step().map_err(|_| statement.error_message())? {
                Step::Done => Ok(None),
                Step::Row => Ok(Some(AuthUser {
                    username: statement.column_text(0),
                    password: statement.column_text(1),
                })),
            }
        })();
        statement.finalize();

        match result {
            Ok(user) => user,
            Err(error) => {
                eprintln!("authentication user lookup failed: {error}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutenroshi::db::Database;
    use crate::mutenroshi::utils::testing::{TEST_SESSION_SECRET, TEST_SESSION_TTL_SECONDS};

    const DATABASE: &str = "file:mutenroshi-auth-repository-test?mode=memory&cache=shared";

    fn execute(database: &Database, sql: &str) {
        let mut statement = database.prepare(sql).expect("failed to prepare test SQL");
        assert_eq!(statement.step(), Ok(Step::Done));
        statement.finalize();
    }

    #[test]
    fn finds_a_user_by_an_exact_username() {
        let mut setup = Database::open_rw(DATABASE).expect("failed to open user test database");
        execute(
            &setup,
            "CREATE TABLE auth_user (username TEXT PRIMARY KEY, password TEXT NOT NULL)",
        );
        execute(
            &setup,
            "INSERT INTO auth_user (username, password) VALUES ('alice', 'correct horse')",
        );
        let context = Context::open(
            DATABASE,
            TEST_SESSION_SECRET.as_bytes().to_vec(),
            TEST_SESSION_TTL_SECONDS,
        )
        .expect("read-only open failed");
        let repository = AuthRepository::new(context.clone());

        assert_eq!(
            repository.user_by("alice"),
            Some(AuthUser {
                username: "alice".to_owned(),
                password: "correct horse".to_owned(),
            })
        );
        assert_eq!(repository.user_by("absent"), None);
        assert_eq!(repository.user_by("alice' OR 1 = 1 --"), None);

        context
            .dbro
            .lock()
            .expect("database mutex is poisoned")
            .close();
        setup.close();
    }
}

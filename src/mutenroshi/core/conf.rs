use std::{env, error::Error, ffi::OsString, fmt, path::PathBuf, sync::LazyLock};

const DEFAULT_SESSION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Eq, PartialEq)]
pub struct Settings {
    pub dbpath: PathBuf,
    pub session_secret: String,
    pub session_ttl_seconds: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SettingsError {
    MissingDbpath,
    MissingSessionSecret,
    InvalidSessionTtlSeconds,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDbpath => formatter.write_str("DBPATH must be set"),
            Self::MissingSessionSecret => formatter.write_str("SESSION_SECRET must be set"),
            Self::InvalidSessionTtlSeconds => {
                formatter.write_str("SESSION_TTL_SECONDS must be a positive integer")
            }
        }
    }
}

impl Error for SettingsError {}

impl Settings {
    pub fn from_env(get_var: impl Fn(&str) -> Option<OsString>) -> Result<Self, SettingsError> {
        let dbpath = get_var("DBPATH").ok_or(SettingsError::MissingDbpath)?;

        let session_secret = get_var("SESSION_SECRET")
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.is_empty())
            .ok_or(SettingsError::MissingSessionSecret)?;

        let session_ttl_seconds = match get_var("SESSION_TTL_SECONDS") {
            None => DEFAULT_SESSION_TTL_SECONDS,
            Some(value) => {
                let value = value
                    .into_string()
                    .map_err(|_| SettingsError::InvalidSessionTtlSeconds)?;
                let parsed = value
                    .parse::<i64>()
                    .map_err(|_| SettingsError::InvalidSessionTtlSeconds)?;
                if parsed <= 0 {
                    return Err(SettingsError::InvalidSessionTtlSeconds);
                }
                parsed
            }
        };

        Ok(Self {
            dbpath: PathBuf::from(dbpath),
            session_secret,
            session_ttl_seconds,
        })
    }
}

#[allow(non_upper_case_globals)]
pub static settings: LazyLock<Settings> = LazyLock::new(|| {
    Settings::from_env(|name| env::var_os(name))
        .unwrap_or_else(|error| panic!("failed to load settings: {error}"))
});

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(
        values: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(*value))
        }
    }

    #[test]
    fn settings_uses_the_injected_dbpath() {
        let parsed = Settings::from_env(env_with(&[
            ("DBPATH", "database.sqlite3"),
            ("SESSION_SECRET", "test-secret"),
        ]))
        .expect("settings parsing failed");

        assert_eq!(parsed.dbpath, PathBuf::from("database.sqlite3"));
    }

    #[test]
    fn settings_requires_dbpath() {
        assert_eq!(
            Settings::from_env(|_| None),
            Err(SettingsError::MissingDbpath)
        );
    }

    #[test]
    fn settings_requires_session_secret() {
        assert_eq!(
            Settings::from_env(env_with(&[("DBPATH", "database.sqlite3")])),
            Err(SettingsError::MissingSessionSecret)
        );
    }

    #[test]
    fn settings_rejects_an_empty_session_secret() {
        assert_eq!(
            Settings::from_env(env_with(&[
                ("DBPATH", "database.sqlite3"),
                ("SESSION_SECRET", ""),
            ])),
            Err(SettingsError::MissingSessionSecret)
        );
    }

    #[test]
    fn settings_defaults_session_ttl_seconds_when_unset() {
        let parsed = Settings::from_env(env_with(&[
            ("DBPATH", "database.sqlite3"),
            ("SESSION_SECRET", "test-secret"),
        ]))
        .expect("settings parsing failed");

        assert_eq!(parsed.session_ttl_seconds, DEFAULT_SESSION_TTL_SECONDS);
    }

    #[test]
    fn settings_uses_the_injected_session_ttl_seconds() {
        let parsed = Settings::from_env(env_with(&[
            ("DBPATH", "database.sqlite3"),
            ("SESSION_SECRET", "test-secret"),
            ("SESSION_TTL_SECONDS", "3600"),
        ]))
        .expect("settings parsing failed");

        assert_eq!(parsed.session_ttl_seconds, 3600);
    }

    #[test]
    fn settings_rejects_a_zero_session_ttl_seconds() {
        assert_eq!(
            Settings::from_env(env_with(&[
                ("DBPATH", "database.sqlite3"),
                ("SESSION_SECRET", "test-secret"),
                ("SESSION_TTL_SECONDS", "0"),
            ])),
            Err(SettingsError::InvalidSessionTtlSeconds)
        );
    }

    #[test]
    fn settings_rejects_a_negative_session_ttl_seconds() {
        assert_eq!(
            Settings::from_env(env_with(&[
                ("DBPATH", "database.sqlite3"),
                ("SESSION_SECRET", "test-secret"),
                ("SESSION_TTL_SECONDS", "-5"),
            ])),
            Err(SettingsError::InvalidSessionTtlSeconds)
        );
    }

    #[test]
    fn settings_rejects_a_non_numeric_session_ttl_seconds() {
        assert_eq!(
            Settings::from_env(env_with(&[
                ("DBPATH", "database.sqlite3"),
                ("SESSION_SECRET", "test-secret"),
                ("SESSION_TTL_SECONDS", "not-a-number"),
            ])),
            Err(SettingsError::InvalidSessionTtlSeconds)
        );
    }
}

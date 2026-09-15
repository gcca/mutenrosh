use std::{
    error::Error as StdError,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const SESSION_COOKIE_NAME: &str = "mutenroshi_session";

#[derive(Debug, Eq, PartialEq)]
pub struct Session {
    pub username: String,
    pub issue_at: i64,
    pub expires_at: i64,
}

#[derive(Deserialize, Serialize)]
struct SessionPayload {
    version: u8,
    salt: String,
    issue_at: i64,
    expires_at: i64,
    username: String,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SessionError {
    Malformed,
    InvalidSignature,
    Expired,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("session token is malformed"),
            Self::InvalidSignature => formatter.write_str("session token signature is invalid"),
            Self::Expired => formatter.write_str("session token has expired"),
        }
    }
}

impl StdError for SessionError {}

fn message(salt: &str, payload_b64: &str) -> Vec<u8> {
    format!("{salt}:{payload_b64}").into_bytes()
}

fn hmac_for(secret: &[u8]) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a secret key of any length")
}

pub fn sign_session(
    username: &str,
    issue_at: i64,
    ttl_seconds: i64,
    secret: &[u8],
    salt: &str,
) -> String {
    let expires_at = issue_at + ttl_seconds;
    let payload = SessionPayload {
        version: 1,
        salt: salt.to_owned(),
        issue_at,
        expires_at,
        username: username.to_owned(),
    };
    let payload = serde_json::to_vec(&payload).expect("session payload is serializable");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

    let mut mac = hmac_for(secret);
    mac.update(&message(salt, &payload_b64));
    let signature_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{payload_b64}.{signature_b64}")
}

pub fn verify_session(token: &str, secret: &[u8], now: i64) -> Result<Session, SessionError> {
    let (payload_b64, supplied_signature_b64) =
        token.split_once('.').ok_or(SessionError::Malformed)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| SessionError::Malformed)?;
    let payload: SessionPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| SessionError::Malformed)?;

    if payload.version != 1 || payload.salt.is_empty() || payload.username.is_empty() {
        return Err(SessionError::Malformed);
    }

    let supplied_signature = URL_SAFE_NO_PAD
        .decode(supplied_signature_b64)
        .map_err(|_| SessionError::Malformed)?;

    let mut mac = hmac_for(secret);
    mac.update(&message(&payload.salt, payload_b64));
    mac.verify_slice(&supplied_signature)
        .map_err(|_| SessionError::InvalidSignature)?;

    if payload.expires_at < now {
        return Err(SessionError::Expired);
    }

    Ok(Session {
        username: payload.username,
        issue_at: payload.issue_at,
        expires_at: payload.expires_at,
    })
}

pub fn generate_salt() -> String {
    let mut raw = [0u8; 12];
    getrandom::fill(&mut raw).expect("failed to read system randomness for a session salt");
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

pub fn create_session_cookie(
    username: &str,
    secret: &[u8],
    ttl_seconds: i64,
    issue_at: i64,
) -> String {
    let salt = generate_salt();
    let token = sign_session(username, issue_at, ttl_seconds, secret, &salt);

    format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl_seconds}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const SECRET: &[u8] = b"test-secret";

    fn sign_raw_payload(payload: &str, salt: &str, secret: &[u8]) -> String {
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let mut mac = hmac_for(secret);
        mac.update(&message(salt, &payload_b64));
        let signature_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload_b64}.{signature_b64}")
    }

    #[test]
    fn sign_and_verify_round_trip_returns_the_original_session() {
        let token = sign_session("alice", 1_000, 100, SECRET, "fixedsalt");
        let payload_b64 = token.split_once('.').expect("token has a separator").0;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("payload is base64url encoded");
        let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload is JSON");

        assert_eq!(payload["version"], 1);
        assert_eq!(payload["issue_at"].as_i64(), Some(1_000));
        assert_eq!(payload["expires_at"].as_i64(), Some(1_100));

        let session = verify_session(&token, SECRET, 1_050).expect("token should verify");

        assert_eq!(session.username, "alice");
        assert_eq!(session.issue_at, 1_000);
        assert_eq!(session.expires_at, 1_100);
    }

    #[test]
    fn verify_session_accepts_a_token_exactly_at_its_expiry() {
        let token = sign_session("alice", 1_000, 100, SECRET, "fixedsalt");

        assert!(verify_session(&token, SECRET, 1_100).is_ok());
    }

    #[test]
    fn verify_session_rejects_a_token_one_second_past_expiry() {
        let token = sign_session("alice", 1_000, 100, SECRET, "fixedsalt");

        assert_eq!(
            verify_session(&token, SECRET, 1_101),
            Err(SessionError::Expired)
        );
    }

    #[test]
    fn verify_session_rejects_a_tampered_signature() {
        let token = sign_session("alice", 1_000, 100, SECRET, "fixedsalt");
        let (payload_b64, signature_b64) = token.split_once('.').expect("token has a separator");
        let mut signature_chars: Vec<char> = signature_b64.chars().collect();
        let index = signature_chars.len() / 2;
        signature_chars[index] = if signature_chars[index] == 'A' {
            'B'
        } else {
            'A'
        };
        let tampered_signature: String = signature_chars.into_iter().collect();
        let tampered = format!("{payload_b64}.{tampered_signature}");

        assert_eq!(
            verify_session(&tampered, SECRET, 1_050),
            Err(SessionError::InvalidSignature)
        );
    }

    #[test]
    fn verify_session_rejects_a_token_signed_with_a_different_secret() {
        let token = sign_session("alice", 1_000, 100, SECRET, "fixedsalt");

        assert_eq!(
            verify_session(&token, b"another-secret", 1_050),
            Err(SessionError::InvalidSignature)
        );
    }

    #[test]
    fn verify_session_rejects_a_token_without_a_separator() {
        assert_eq!(
            verify_session("not-a-token", SECRET, 1_050),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn verify_session_rejects_invalid_base64_payload() {
        assert_eq!(
            verify_session("not*base64!.signature", SECRET, 1_050),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn verify_session_rejects_a_legacy_colon_delimited_payload() {
        let token = sign_raw_payload("salt:1000:2000:alice", "salt", SECRET);

        assert_eq!(
            verify_session(&token, SECRET, 1_050),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn verify_session_rejects_a_payload_missing_a_required_field() {
        let token = sign_raw_payload(
            r#"{"version":1,"salt":"salt","issue_at":1000,"expires_at":2000}"#,
            "salt",
            SECRET,
        );

        assert_eq!(
            verify_session(&token, SECRET, 1_050),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn verify_session_rejects_a_payload_with_an_invalid_required_field() {
        let token = sign_raw_payload(
            r#"{"version":1,"salt":123,"issue_at":1000,"expires_at":2000,"username":"alice"}"#,
            "salt",
            SECRET,
        );

        assert_eq!(
            verify_session(&token, SECRET, 1_050),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn verify_session_rejects_non_integer_timestamps() {
        for payload in [
            r#"{"version":1,"salt":"salt","issue_at":1000.5,"expires_at":2000,"username":"alice"}"#,
            r#"{"version":1,"salt":"salt","issue_at":1000,"expires_at":"2000","username":"alice"}"#,
        ] {
            let token = sign_raw_payload(payload, "salt", SECRET);

            assert_eq!(
                verify_session(&token, SECRET, 1_050),
                Err(SessionError::Malformed)
            );
        }
    }

    #[test]
    fn verify_session_rejects_an_unsupported_version() {
        let token = sign_raw_payload(
            r#"{"version":2,"salt":"salt","issue_at":1000,"expires_at":2000,"username":"alice"}"#,
            "salt",
            SECRET,
        );

        assert_eq!(
            verify_session(&token, SECRET, 1_050),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn verify_session_accepts_a_signed_payload_with_an_extra_field() {
        let payload = json!({
            "version": 1,
            "salt": "salt",
            "issue_at": 1_000,
            "expires_at": 2_000,
            "username": "alice",
            "extra": "accepted",
        });
        let token = sign_raw_payload(&payload.to_string(), "salt", SECRET);

        assert_eq!(
            verify_session(&token, SECRET, 1_050),
            Ok(Session {
                username: "alice".to_owned(),
                issue_at: 1_000,
                expires_at: 2_000,
            })
        );
    }

    #[test]
    fn sign_session_with_different_salts_produces_different_tokens() {
        let first = sign_session("alice", 1_000, 100, SECRET, "saltone");
        let second = sign_session("alice", 1_000, 100, SECRET, "salttwo");

        assert_ne!(first, second);
    }

    #[test]
    fn generate_salt_uses_a_url_safe_base64_alphabet_of_the_expected_length() {
        let salt = generate_salt();

        assert_eq!(salt.len(), 16);
        assert!(
            salt.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn generate_salt_produces_different_values_across_calls() {
        assert_ne!(generate_salt(), generate_salt());
    }

    #[test]
    fn create_session_cookie_has_the_expected_name_and_attributes() {
        let cookie = create_session_cookie("alice", SECRET, 3_600, 1_000);

        assert!(cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=3600"));
    }

    #[test]
    fn create_session_cookie_token_round_trips_through_verify_session() {
        let cookie = create_session_cookie("alice", SECRET, 3_600, 1_000);
        let name_and_token = cookie.split_once(';').expect("cookie has attributes").0;
        let token = name_and_token
            .split_once('=')
            .expect("cookie has a name=value pair")
            .1;

        let session = verify_session(token, SECRET, 1_050).expect("issued cookie should verify");

        assert_eq!(session.username, "alice");
        assert_eq!(session.expires_at - session.issue_at, 3_600);
    }

    #[test]
    fn now_unix_returns_a_plausible_current_timestamp() {
        assert!(now_unix() > 1_700_000_000);
    }
}

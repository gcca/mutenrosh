use axum::{
    Router,
    body::Body,
    http::{Method, Request},
    response::Response,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::mutenroshi::core::Context;

pub const TEST_SESSION_SECRET: &str = "mutenroshi-test-session-secret";
pub const TEST_SESSION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

pub struct TestContext {
    pub context: Context,
}

pub fn test_context() -> TestContext {
    let context = Context::open(
        ":memory:",
        TEST_SESSION_SECRET.as_bytes().to_vec(),
        TEST_SESSION_TTL_SECONDS,
    )
    .expect("failed to open test context");

    TestContext { context }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.context
            .dbro
            .lock()
            .expect("test database mutex is poisoned")
            .close();
    }
}

pub fn request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("failed to build the test request")
}

pub async fn dispatch(router: Router, method: Method, uri: &str) -> Response {
    router
        .oneshot(request(method, uri))
        .await
        .expect("router dispatch failed")
}

pub async fn dispatch_form(router: Router, uri: &str, form: &str) -> Response {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form.to_owned()))
        .expect("failed to build the form request");

    router
        .oneshot(request)
        .await
        .expect("router dispatch failed")
}

pub async fn body_of(response: Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to collect the response body")
        .to_bytes();

    String::from_utf8(bytes.to_vec()).expect("the response body is not valid UTF-8")
}

pub fn location_of(response: &Response) -> &str {
    response
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("the response has no Location header")
        .to_str()
        .expect("the Location header is not valid UTF-8")
}

pub fn set_cookie_of(response: &Response) -> &str {
    response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("the response has no Set-Cookie header")
        .to_str()
        .expect("the Set-Cookie header is not valid UTF-8")
}

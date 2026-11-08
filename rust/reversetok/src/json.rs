use serde::Serialize;

use crate::error::Result;

#[derive(Serialize)]
struct FfiResponse<T> {
    ok: bool,
    result: Option<T>,
    error: Option<String>,
}

pub fn respond<T: Serialize>(result: Result<T>) -> String {
    let response = match result {
        Ok(value) => FfiResponse {
            ok: true,
            result: Some(value),
            error: None,
        },
        Err(error) => FfiResponse {
            ok: false,
            result: None,
            error: Some(error.to_string()),
        },
    };
    serde_json::to_string(&response)
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialization failed\"}".into())
}

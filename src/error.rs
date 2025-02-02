use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;
use tracing::error;

/// `axum`-compatible error handler.
#[derive(Error)]
pub struct Error {
    status: StatusCode,
    err: anyhow::Error,
}

impl Error {
    pub fn with_status(status: StatusCode, err: impl Into<anyhow::Error>) -> Self {
        Self {
            status,
            err: err.into(),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            err,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.err)
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.err.fmt(f)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        error!("{:?}", self.err);

        // N.B: Forward out the error message to the requester if this is a debug build.
        // This is insecure for production builds, so we'll return an empty body if this
        // is a release build.
        if cfg!(debug_assertions) {
            (self.status, format!("{:?}", self.err)).into_response()
        } else {
            self.status.into_response()
        }
    }
}

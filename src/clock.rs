//! The server's clock. An offset simulates an identity provider whose clock runs ahead of (or
//! behind) real time: it shifts the timestamps written into assertions (`IssueInstant`,
//! `NotBefore`, `NotOnOrAfter`, `AuthnInstant`, ...) and every expiry check (sessions, pending
//! logins, ...). It lives in memory only, so a restart always goes back to real time.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::util::wall_clock;

#[derive(Debug, Clone, Default)]
pub struct Clock {
    offset: Arc<AtomicI64>,
}

impl Clock {
    pub fn new(offset: i64) -> Self {
        Self { offset: Arc::new(AtomicI64::new(offset)) }
    }

    /// The server's idea of now: real time plus the offset, in Unix seconds.
    pub fn now(&self) -> i64 {
        wall_clock() + self.offset()
    }

    /// Seconds the clock is ahead of real time (negative when behind).
    pub fn offset(&self) -> i64 {
        self.offset.load(Ordering::Relaxed)
    }

    pub fn set_offset(&self, offset: i64) {
        self.offset.store(offset, Ordering::Relaxed);
    }

    pub fn advance(&self, by: i64) -> i64 {
        self.offset.fetch_add(by, Ordering::Relaxed) + by
    }
}

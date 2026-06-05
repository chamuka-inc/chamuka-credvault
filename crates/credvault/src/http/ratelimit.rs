//! A small per-IP fixed-window rate limiter, applied as middleware to the API surface.
//!
//! It is a coarse abuse/DoS backstop — enough to blunt credential enumeration and stop a
//! single source from forcing unbounded upstream token exchanges — not a precise quota
//! system. Counters live in-process (per web replica); a multi-node deployment that needs
//! a global budget would front this with a shared store, but the local limiter still caps
//! each replica. Disabled when `rate_limit_per_minute == 0`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

const WINDOW: Duration = Duration::from_secs(60);
/// Drop idle IP entries beyond this many to bound memory under address churn/spoofing.
const MAX_TRACKED_IPS: usize = 100_000;

struct Bucket {
    window_start: Instant,
    count: u32,
}

pub struct RateLimiter {
    per_minute: u32,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Arc<Self> {
        Arc::new(Self {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Record a request from `ip`; return `true` if it is within budget.
    fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let mut buckets = self.buckets.lock().expect("rate-limit mutex");

        if buckets.len() > MAX_TRACKED_IPS {
            buckets.retain(|_, b| now.duration_since(b.window_start) < WINDOW);
        }

        let bucket = buckets.entry(ip).or_insert(Bucket {
            window_start: now,
            count: 0,
        });
        if now.duration_since(bucket.window_start) >= WINDOW {
            bucket.window_start = now;
            bucket.count = 0;
        }
        if bucket.count >= self.per_minute {
            return false;
        }
        bucket.count += 1;
        true
    }
}

/// Axum middleware enforcing [`RateLimiter`]. Keyed on the peer socket address, so the
/// server must be served with connect-info (`into_make_service_with_connect_info`).
pub async fn enforce(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if limiter.allow(peer.ip(), Instant::now()) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "code": "rate_limited", "message": "too many requests" })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_budget_then_blocks_then_resets() {
        let rl = RateLimiter::new(3);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.allow(ip, t0));
        assert!(rl.allow(ip, t0));
        assert!(rl.allow(ip, t0));
        assert!(!rl.allow(ip, t0), "4th in-window request is blocked");
        // A different IP has its own budget.
        let ip2: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(rl.allow(ip2, t0));
        // After the window elapses, the original IP is allowed again.
        let later = t0 + WINDOW + Duration::from_secs(1);
        assert!(rl.allow(ip, later));
    }

    #[test]
    fn zero_disables() {
        let rl = RateLimiter::new(0);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert!(rl.allow(ip, t0));
        }
    }
}

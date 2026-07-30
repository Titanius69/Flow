//! Connection and login rate limiting.
//!
//! Without these, a single host can open sockets until the proxy runs out of
//! file descriptors, and every one of those sockets also makes the proxy dial
//! the backend, so the attack amplifies onto Paper as well.
//!
//! The bookkeeping is itself bounded: a naive `HashMap` keyed by IP is a memory
//! exhaustion vector of its own, so stale entries are pruned.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many login timestamps to keep before pruning expired ones.
const PRUNE_THRESHOLD: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum concurrent connections across the whole proxy. `0` disables.
    pub connection_limit: usize,
    /// Maximum concurrent connections from one address. `0` disables.
    pub connections_per_ip: usize,
    /// Minimum gap between login attempts from one address. `0` disables.
    pub login_ratelimit: Duration,
}

/// Why a connection was turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The proxy is at its global connection limit.
    ProxyFull,
    /// This address already has too many connections open.
    TooManyFromAddress,
}

#[derive(Default)]
struct State {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    last_login: HashMap<IpAddr, Instant>,
}

pub struct Limiter {
    limits: Limits,
    state: Mutex<State>,
}

impl Limiter {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::new(State::default()),
        })
    }

    /// Accounts for a new connection. The returned guard releases it on drop,
    /// so every early return and every panic still frees the slot.
    pub fn accept(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionGuard, Reject> {
        let mut state = self.state.lock().expect("limiter mutex poisoned");

        if self.limits.connection_limit > 0 && state.total >= self.limits.connection_limit {
            return Err(Reject::ProxyFull);
        }

        let per_ip = state.per_ip.entry(ip).or_insert(0);
        if self.limits.connections_per_ip > 0 && *per_ip >= self.limits.connections_per_ip {
            return Err(Reject::TooManyFromAddress);
        }

        *per_ip += 1;
        state.total += 1;

        Ok(ConnectionGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Checks the login rate limit, recording the attempt when it is allowed.
    ///
    /// Returns how long the caller must wait when it is not.
    pub fn check_login(&self, ip: IpAddr) -> Result<(), Duration> {
        if self.limits.login_ratelimit.is_zero() {
            return Ok(());
        }

        let now = Instant::now();
        let mut state = self.state.lock().expect("limiter mutex poisoned");

        if let Some(previous) = state.last_login.get(&ip) {
            let elapsed = now.saturating_duration_since(*previous);
            if elapsed < self.limits.login_ratelimit {
                return Err(self.limits.login_ratelimit - elapsed);
            }
        }

        if state.last_login.len() >= PRUNE_THRESHOLD {
            let window = self.limits.login_ratelimit;
            state
                .last_login
                .retain(|_, t| now.saturating_duration_since(*t) < window);
        }

        state.last_login.insert(ip, now);
        Ok(())
    }

    /// Current number of open connections, for logging and tests.
    pub fn open_connections(&self) -> usize {
        self.state.lock().expect("limiter mutex poisoned").total
    }

    fn release(&self, ip: IpAddr) {
        let mut state = self.state.lock().expect("limiter mutex poisoned");
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_ip.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                // Drop the key so idle addresses do not accumulate.
                state.per_ip.remove(&ip);
            }
        }
    }
}

/// Holds a connection slot for as long as it lives.
pub struct ConnectionGuard {
    limiter: Arc<Limiter>,
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(total: usize, per_ip: usize, ratelimit_ms: u64) -> Limits {
        Limits {
            connection_limit: total,
            connections_per_ip: per_ip,
            login_ratelimit: Duration::from_millis(ratelimit_ms),
        }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn per_ip_limit_is_enforced() {
        let limiter = Limiter::new(limits(100, 2, 0));
        let _a = limiter.accept(ip(1)).unwrap();
        let _b = limiter.accept(ip(1)).unwrap();
        assert_eq!(limiter.accept(ip(1)).err(), Some(Reject::TooManyFromAddress));
        // A different address is unaffected.
        assert!(limiter.accept(ip(2)).is_ok());
    }

    #[test]
    fn global_limit_is_enforced() {
        let limiter = Limiter::new(limits(2, 0, 0));
        let _a = limiter.accept(ip(1)).unwrap();
        let _b = limiter.accept(ip(2)).unwrap();
        assert_eq!(limiter.accept(ip(3)).err(), Some(Reject::ProxyFull));
    }

    #[test]
    fn dropping_a_guard_frees_the_slot() {
        let limiter = Limiter::new(limits(1, 1, 0));
        {
            let _a = limiter.accept(ip(1)).unwrap();
            assert_eq!(limiter.open_connections(), 1);
            assert!(limiter.accept(ip(1)).is_err());
        }
        assert_eq!(limiter.open_connections(), 0);
        assert!(limiter.accept(ip(1)).is_ok());
    }

    #[test]
    fn idle_addresses_do_not_accumulate() {
        let limiter = Limiter::new(limits(0, 0, 0));
        for n in 0..50 {
            let _guard = limiter.accept(ip(n)).unwrap();
        }
        let state = limiter.state.lock().unwrap();
        assert!(
            state.per_ip.is_empty(),
            "per-IP entries should be removed once a connection closes"
        );
    }

    #[test]
    fn zero_means_unlimited() {
        let limiter = Limiter::new(limits(0, 0, 0));
        let mut guards = Vec::new();
        for _ in 0..200 {
            guards.push(limiter.accept(ip(1)).unwrap());
        }
        assert_eq!(limiter.open_connections(), 200);
    }

    #[test]
    fn login_ratelimit_rejects_a_second_attempt() {
        let limiter = Limiter::new(limits(0, 0, 60_000));
        assert!(limiter.check_login(ip(1)).is_ok());
        assert!(limiter.check_login(ip(1)).is_err());
        // Another address is not affected.
        assert!(limiter.check_login(ip(2)).is_ok());
    }

    #[test]
    fn login_ratelimit_allows_the_attempt_after_the_window() {
        let limiter = Limiter::new(limits(0, 0, 1));
        assert!(limiter.check_login(ip(1)).is_ok());
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check_login(ip(1)).is_ok());
    }

    #[test]
    fn login_ratelimit_disabled_by_zero() {
        let limiter = Limiter::new(limits(0, 0, 0));
        for _ in 0..10 {
            assert!(limiter.check_login(ip(1)).is_ok());
        }
    }

    #[test]
    fn login_timestamps_are_pruned() {
        let limiter = Limiter::new(limits(0, 0, 1));
        for n in 0..255u8 {
            let _ = limiter.check_login(IpAddr::from([10, 0, 1, n]));
        }
        std::thread::sleep(Duration::from_millis(5));
        // Push past the prune threshold.
        for n in 0..255u8 {
            for m in 0..20u8 {
                let _ = limiter.check_login(IpAddr::from([172, 16, m, n]));
            }
        }
        let state = limiter.state.lock().unwrap();
        assert!(
            state.last_login.len() < 6000,
            "expired login timestamps should be dropped, had {}",
            state.last_login.len()
        );
    }
}

use komainu_application::Clock;
use time::OffsetDateTime;

/// Wall clock backed by the system time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_utc_and_close_to_system_time() {
        let now = SystemClock.now();
        assert!(now.offset().is_utc());
        let delta = (OffsetDateTime::now_utc() - now).abs();
        assert!(delta < time::Duration::seconds(5));
    }
}

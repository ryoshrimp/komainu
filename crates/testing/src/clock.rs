use std::sync::{Arc, Mutex};

use komainu_application::Clock;
use time::{Duration, OffsetDateTime};

/// A clock that only moves when told to.
#[derive(Clone)]
pub struct FixedClock {
    now: Arc<Mutex<OffsetDateTime>>,
}

impl FixedClock {
    pub fn new(at: OffsetDateTime) -> Self {
        Self {
            now: Arc::new(Mutex::new(at)),
        }
    }

    pub fn set(&self, at: OffsetDateTime) {
        *self.now.lock().unwrap() = at;
    }

    pub fn advance(&self, by: Duration) {
        *self.now.lock().unwrap() += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_advance() {
        let clock = FixedClock::new(OffsetDateTime::UNIX_EPOCH);
        let shared = clock.clone();
        clock.advance(Duration::seconds(90));
        assert_eq!(shared.now().unix_timestamp(), 90);
        shared.set(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(clock.now(), OffsetDateTime::UNIX_EPOCH);
    }
}

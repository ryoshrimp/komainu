use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use komainu_application::SecureRandom;

/// Deterministic: fills bytes from an incrementing u64 counter (little endian, repeated).
/// Each call uses the next counter value, so buffers of 8 or more bytes differ between calls
/// (a shorter buffer only sees a prefix of the counter, which can repeat).
#[derive(Clone, Default)]
pub struct SequenceRandom {
    counter: Arc<AtomicU64>,
}

impl SecureRandom for SequenceRandom {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        for (byte, source) in dest.iter_mut().zip(n.to_le_bytes().into_iter().cycle()) {
            *byte = source;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_is_little_endian_and_repeated() {
        let random = SequenceRandom::default();
        let mut first = [0xffu8; 10];
        random.fill_bytes(&mut first);
        assert_eq!(first, [0; 10]);
        let mut second = [0u8; 10];
        random.fill_bytes(&mut second);
        assert_eq!(second, [1, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }
}

use time::OffsetDateTime;

pub trait Clock: Send + Sync + 'static {
    /// Current time in UTC.
    fn now(&self) -> OffsetDateTime;
}

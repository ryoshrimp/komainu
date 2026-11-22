pub trait SecureRandom: Send + Sync + 'static {
    /// Fills dest with bytes from a CSPRNG.
    fn fill_bytes(&self, dest: &mut [u8]);
}

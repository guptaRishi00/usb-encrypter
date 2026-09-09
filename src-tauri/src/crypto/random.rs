//! The single place VaultDrive obtains randomness.
//!
//! Everything goes through the operating system CSPRNG (`OsRng`, re-exported by
//! the `aead` crate on top of `getrandom`). There is no seeded, deterministic or
//! user-supplied randomness anywhere in the vault format.

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;

/// Fill `buf` with cryptographically secure random bytes.
///
/// Panics rather than continuing if the OS entropy source fails. Silently
/// producing a weak nonce or salt would be far worse than a crash.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill_random(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let a: [u8; 32] = random_array();
        let b: [u8; 32] = random_array();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}

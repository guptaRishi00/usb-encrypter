//! Cryptographic primitives.
//!
//! Nothing in this module implements an algorithm. Argon2id comes from the
//! `argon2` crate, XChaCha20-Poly1305 and the STREAM chunking from
//! `chacha20poly1305`/`aead`, HKDF from `hkdf`, all RustCrypto. This module
//! only wires them together and decides what is bound as associated data.

pub mod aead;
pub mod kdf;
pub mod keys;
pub mod random;

pub use kdf::{derive_kek, KdfParams};
pub use keys::MasterKey;

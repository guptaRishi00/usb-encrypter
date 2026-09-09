//! Password-based key derivation.
//!
//! Argon2id only, via the RustCrypto `argon2` crate. Nothing here is
//! hand-rolled. The password is held in a `Zeroizing` buffer and wiped on drop,
//! and the derived key-encryption key never leaves this module unwrapped.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Upper bound on the memory a vault header may ask us to allocate.
///
/// The header is attacker-controlled before the password is checked, so a
/// hostile `.vault` could otherwise ask for a terabyte and take the process
/// down. 2 GiB is far above any parameter set we would ever write.
const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

/// Non-secret Argon2id parameters. Stored in the vault header in the clear so
/// any future build can still open the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::interactive()
    }
}

impl KdfParams {
    /// The parameters VaultDrive writes into every new vault.
    ///
    /// 128 MiB / 3 passes / 4 lanes. Comfortably above the OWASP 2024 floor for
    /// Argon2id (19 MiB, t=2, p=1) while staying usable on a laptop; unlocking
    /// costs roughly a quarter of a second and a GPU attacker pays the full
    /// 128 MiB per guess.
    pub const fn interactive() -> Self {
        Self { m_cost_kib: 131_072, t_cost: 3, p_cost: 4 }
    }

    /// Deliberately weak parameters so the test suite can create hundreds of
    /// vaults in seconds.
    ///
    /// Never used by the application. A vault created with these is not
    /// meaningfully protected against offline guessing.
    pub const fn insecure_fast_for_tests() -> Self {
        Self { m_cost_kib: 8, t_cost: 1, p_cost: 1 }
    }

    fn validate(&self) -> Result<()> {
        if self.m_cost_kib > MAX_M_COST_KIB
            || self.t_cost > MAX_T_COST
            || self.p_cost > MAX_P_COST
            || self.t_cost == 0
            || self.p_cost == 0
        {
            return Err(VaultError::UnsupportedKdfParameters);
        }
        Ok(())
    }
}

/// A 32-byte key-encryption key. Wiped on drop.
pub type Kek = Zeroizing<[u8; 32]>;

/// Derive the key-encryption key from a password and the vault's salt.
///
/// The password is consumed by reference and never copied anywhere else; the
/// caller owns wiping it. The returned KEK is only ever used to unwrap the
/// vault's master key.
pub fn derive_kek(password: &[u8], salt: &[u8; 32], params: KdfParams) -> Result<Kek> {
    params.validate()?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(32),
    )
    .map_err(|_| VaultError::UnsupportedKdfParameters)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut kek: Kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, kek.as_mut())
        .map_err(|_| VaultError::UnsupportedKdfParameters)?;

    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_and_salt_give_the_same_key() {
        let p = KdfParams::insecure_fast_for_tests();
        let salt = [7u8; 32];
        let a = derive_kek(b"correct horse", &salt, p).unwrap();
        let b = derive_kek(b"correct horse", &salt, p).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_salt_gives_a_different_key() {
        let p = KdfParams::insecure_fast_for_tests();
        let a = derive_kek(b"correct horse", &[1u8; 32], p).unwrap();
        let b = derive_kek(b"correct horse", &[2u8; 32], p).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn absurd_memory_cost_is_refused_rather_than_allocated() {
        let bad = KdfParams { m_cost_kib: u32::MAX, t_cost: 3, p_cost: 4 };
        assert!(derive_kek(b"x", &[0u8; 32], bad).is_err());
    }

    #[test]
    fn zero_passes_is_refused() {
        let bad = KdfParams { m_cost_kib: 8, t_cost: 0, p_cost: 1 };
        assert!(derive_kek(b"x", &[0u8; 32], bad).is_err());
    }
}

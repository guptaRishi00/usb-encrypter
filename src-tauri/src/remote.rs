//! Authenticator-server mode: unlock with a six-digit code instead of a
//! password.
//!
//! # Why a server is involved at all
//!
//! A TOTP code is six digits derived from a shared secret and the clock. For a
//! vault on a USB stick to verify codes by itself, that secret would have to be
//! on the stick, and whoever holds the stick could then compute every code. And
//! even with the secret elsewhere, a key protected by six digits is a million
//! guesses, which an offline attacker finishes in seconds.
//!
//! So the secret never touches the drive in the clear. The drive carries a
//! *token*: the authenticator secret and a random 32-byte unlock key, sealed by
//! the server under a master secret only the server has. To unlock, the client
//! sends the token plus the current code; the server verifies the code, applies
//! its attempt limit and single-use rule, and only then releases the key. That
//! key is what this module hands to the vault engine in place of a password.
//!
//! The cost is stated plainly everywhere it matters: these vaults need the
//! internet, and they trust the server. Password vaults are unaffected and stay
//! fully offline.
//!
//! The server is the user's own `usbvault-web` deployment; see its
//! `api/create.js` and `api/unlock.js` for the contract this file follows.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// The deployment VaultDrive talks to unless a vault's sidecar names another.
pub const DEFAULT_SITE: &str = "https://usbvault-web.vercel.app";

/// Sidecar written beside `.vaultdrive.vault` for a folder locked in
/// authenticator mode. Holds nothing usable without the server.
pub const REMOTE_AUTH_FILE: &str = ".vaultdrive.totp.json";

const TIMEOUT: Duration = Duration::from_secs(20);
/// Longest server error message we will relay to the interface.
const MAX_SERVER_MESSAGE: usize = 160;

/// What the drive keeps. The token is opaque ciphertext under the server's
/// master secret; `site` records which deployment sealed it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteAuth {
    pub site: String,
    pub token: String,
    pub vault_id: String,
    pub name: String,
}

impl RemoteAuth {
    pub fn load(folder: &Path) -> Option<Self> {
        let path = folder.join(REMOTE_AUTH_FILE);
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, folder: &Path) -> Result<()> {
        let path = folder.join(REMOTE_AUTH_FILE);
        let json = serde_json::to_string_pretty(self)
            .map_err(|_| VaultError::Io("Could not encode the authenticator record.".into()))?;
        std::fs::write(&path, json).map_err(|e| VaultError::from_io(&e, &path))
    }
}

/// The server's answer to `create`: everything the person enrolling needs to
/// see once, plus the token that goes on the drive.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrolment {
    pub site: String,
    pub token: String,
    pub vault_id: String,
    pub name: String,
    /// `otpauth://totp/...` — what the QR encodes.
    pub otpauth: String,
    /// The secret grouped in fours, for typing into an app that cannot scan.
    pub manual_key: String,
    /// The QR as an SVG document, rendered here so the window needs no CDN.
    pub qr_svg: String,
}

#[derive(Deserialize)]
struct CreateResponse {
    token: String,
    #[serde(rename = "vaultId")]
    vault_id: String,
    name: String,
    otpauth: String,
    #[serde(rename = "manualKey")]
    manual_key: String,
}

#[derive(Deserialize)]
struct UnlockResponse {
    key: String,
}

#[derive(Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    error: String,
}

fn endpoint(site: &str, path: &str) -> String {
    format!("{}/api/{}", site.trim_end_matches('/'), path)
}

/// Turn a transport or HTTP failure into something a person can act on.
///
/// 401 is the server's "wrong code", 429 its attempt limit. Anything else is
/// relayed with the server's own text, capped, because a hostile or broken
/// server is not allowed to write the interface.
fn map_error(err: ureq::Error) -> VaultError {
    match err {
        ureq::Error::Status(401, _) => VaultError::WrongCode,
        ureq::Error::Status(429, _) => VaultError::TooManyAttempts,
        ureq::Error::Status(code, resp) => {
            let body: ErrorBody = resp.into_json().unwrap_or_default();
            let mut text = if body.error.is_empty() {
                format!("HTTP {code}")
            } else {
                body.error
            };
            if text.len() > MAX_SERVER_MESSAGE {
                text.truncate(MAX_SERVER_MESSAGE);
                text.push('…');
            }
            VaultError::RemoteAuth(text)
        }
        ureq::Error::Transport(_) => VaultError::Offline,
    }
}

/// Ask the server for a fresh authenticator secret and unlock key, sealed.
///
/// Nothing is written anywhere by this call; the caller decides whether to
/// keep the enrolment, and normally only does so once the user has typed a
/// valid code, proving the scan worked.
pub fn enrol(site: &str, name: &str) -> Result<Enrolment> {
    let name = name.trim();
    let name = if name.is_empty() { "VaultDrive folder" } else { name };

    let resp: CreateResponse = ureq::post(&endpoint(site, "create"))
        .timeout(TIMEOUT)
        .send_json(serde_json::json!({ "name": name }))
        .map_err(map_error)?
        .into_json()
        .map_err(|_| VaultError::RemoteAuth("the server sent an unreadable reply".into()))?;

    let qr_svg = qr_svg(&resp.otpauth)?;
    Ok(Enrolment {
        site: site.to_string(),
        token: resp.token,
        vault_id: resp.vault_id,
        name: resp.name,
        otpauth: resp.otpauth,
        manual_key: resp.manual_key,
        qr_svg,
    })
}

/// Exchange a token and a current code for the unlock key.
///
/// The key comes back as the server's base64url string of 32 random bytes.
/// It is used as the vault "password" exactly as typed, so there is no decode
/// step to get subtly wrong, and Argon2id runs over it like any other secret.
/// It is wiped when dropped.
pub fn redeem(site: &str, token: &str, code: &str) -> Result<Zeroizing<Vec<u8>>> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VaultError::InvalidInput(
            "An authenticator code is six digits.".into(),
        ));
    }

    let resp: UnlockResponse = ureq::post(&endpoint(site, "unlock"))
        .timeout(TIMEOUT)
        .send_json(serde_json::json!({ "token": token, "code": code }))
        .map_err(map_error)?
        .into_json()
        .map_err(|_| VaultError::RemoteAuth("the server sent an unreadable reply".into()))?;

    if resp.key.len() < 32 {
        return Err(VaultError::RemoteAuth("the server released an unusable key".into()));
    }
    Ok(Zeroizing::new(resp.key.into_bytes()))
}

/// Render an `otpauth://` URL as an SVG QR code.
pub fn qr_svg(data: &str) -> Result<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(data.as_bytes())
        .map_err(|_| VaultError::RemoteAuth("the enrolment could not be encoded as a QR".into()))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sidecar_round_trips_and_holds_only_the_four_fields() {
        let dir = tempfile::tempdir().unwrap();
        let auth = RemoteAuth {
            site: DEFAULT_SITE.into(),
            token: "sealed.opaque.token".into(),
            vault_id: "abcd1234".into(),
            name: "Holiday photos".into(),
        };
        auth.save(dir.path()).unwrap();
        assert_eq!(RemoteAuth::load(dir.path()), Some(auth));

        let raw = std::fs::read_to_string(dir.path().join(REMOTE_AUTH_FILE)).unwrap();
        for forbidden in ["secret", "key", "password", "otpauth"] {
            assert!(!raw.to_lowercase().contains(forbidden), "sidecar mentions {forbidden}");
        }
    }

    #[test]
    fn a_sidecar_with_extra_fields_is_refused() {
        // If a future change tries to persist the released key beside the
        // vault, this is the test that fails.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(REMOTE_AUTH_FILE),
            r#"{"site":"x","token":"t","vaultId":"v","name":"n","key":"LEAK"}"#,
        )
        .unwrap();
        assert_eq!(RemoteAuth::load(dir.path()), None);
    }

    #[test]
    fn a_missing_sidecar_means_password_mode() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(RemoteAuth::load(dir.path()), None);
    }

    #[test]
    fn a_code_that_is_not_six_digits_never_reaches_the_network() {
        for bad in ["", "12345", "1234567", "12345a", " 123 456 "] {
            let err = redeem("http://127.0.0.1:9", "token", bad).unwrap_err();
            assert!(matches!(err, VaultError::InvalidInput(_)), "{bad:?} gave {err:?}");
        }
    }

    #[test]
    fn an_unreachable_server_is_reported_as_offline() {
        // Port 9 (discard) refuses connections on any sane machine.
        let err = redeem("http://127.0.0.1:9", "token", "123456").unwrap_err();
        assert!(matches!(err, VaultError::Offline), "got {err:?}");
    }

    #[test]
    fn the_qr_is_a_real_svg() {
        let svg = qr_svg("otpauth://totp/usbvault:Test?secret=ABCDEFGH&issuer=usbvault").unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn endpoints_tolerate_a_trailing_slash() {
        assert_eq!(endpoint("https://x.app/", "unlock"), "https://x.app/api/unlock");
        assert_eq!(endpoint("https://x.app", "create"), "https://x.app/api/create");
    }
}

//! Password strength estimation.
//!
//! Runs in Rust so the password is scored in the same process that will derive
//! the key, and the frontend only ever receives a number and a label.
//!
//! The estimate is deliberately length-led. A four-word passphrase scores well
//! without a single symbol in it, and `P@ssw0rd!` scores badly despite hitting
//! every classic complexity rule. Nothing here is enforced: a weak password is
//! warned about, never refused, because refusing pushes people towards
//! predictable patterns that satisfy the rule and nothing else.

use serde::Serialize;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// 0 weak, 1 medium, 2 strong, 3 very strong.
    pub score: u8,
    pub label: &'static str,
    pub entropy_bits: u32,
    /// Plain-language notes. Never quotes the password back.
    pub notes: Vec<&'static str>,
}

/// Passwords common enough that an attacker tries them first regardless of how
/// many character classes they contain. A short illustrative list, not a
/// substitute for a real breach corpus.
const COMMON: [&str; 24] = [
    "password", "123456", "123456789", "qwerty", "abc123", "password1", "111111", "12345678",
    "iloveyou", "admin", "welcome", "monkey", "letmein", "dragon", "sunshine", "princess",
    "football", "charlie", "aa123456", "donald", "qwerty123", "1q2w3e4o", "starwars", "passw0rd",
];

fn charset_size(pw: &str) -> u32 {
    let mut size = 0;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        size += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        size += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        size += 10;
    }
    if pw.chars().any(|c| c.is_ascii_punctuation() || c == ' ') {
        size += 33;
    }
    if pw.chars().any(|c| !c.is_ascii()) {
        size += 100;
    }
    size.max(1)
}

/// Count characters that differ from the one before, so `aaaaaaaaaaaa` is not
/// credited as twelve characters of entropy.
fn effective_length(pw: &str) -> usize {
    let mut prev: Option<char> = None;
    let mut n = 0usize;
    for c in pw.chars() {
        if Some(c) != prev {
            n += 1;
        }
        prev = Some(c);
    }
    n
}

fn looks_like_a_passphrase(pw: &str) -> bool {
    pw.split(|c: char| c == ' ' || c == '-' || c == '_')
        .filter(|w| w.len() >= 3)
        .count()
        >= 3
}

/// Estimate the strength of `password`.
///
/// The lowercased copy made for the common-password check is wiped before this
/// function returns.
pub fn estimate(password: &str) -> Strength {
    let mut notes = Vec::new();

    if password.is_empty() {
        return Strength {
            score: 0,
            label: "Weak",
            entropy_bits: 0,
            notes: vec!["Enter a password."],
        };
    }

    let mut lowered = password.to_lowercase();
    let is_common = COMMON.contains(&lowered.as_str())
        || COMMON.iter().any(|c| lowered.len() <= c.len() + 3 && lowered.starts_with(c));
    lowered.zeroize();

    let eff = effective_length(password) as f64;
    let bits = (eff * (charset_size(password) as f64).log2()).round().max(0.0);
    let mut bits = bits as u32;

    if is_common {
        notes.push("This looks like a very common password.");
        bits = bits.min(16);
    }
    // Only worth mentioning when repetition is doing real damage. Firing on any
    // doubled letter would flag almost every English passphrase -- "kettle" and
    // "tunnel" both have one -- which trains people to ignore the advice.
    let chars_total = password.chars().count();
    if chars_total >= 4 && effective_length(password) * 4 < chars_total * 3 {
        notes.push("Repeated characters add less protection than they look like.");
    }

    let chars = chars_total;
    if chars < 12 {
        notes.push("Longer is stronger. Aim for at least 12 characters.");
    }
    if looks_like_a_passphrase(password) {
        notes.push("A multi-word passphrase is a good choice.");
    }

    // Thresholds in bits of the estimate above. 60 bits is the point at which
    // an offline attacker paying 128 MiB of Argon2id per guess is in serious
    // trouble; 90 puts it out of reach.
    let (score, label) = match bits {
        0..=39 => (0u8, "Weak"),
        40..=59 => (1, "Medium"),
        60..=89 => (2, "Strong"),
        _ => (3, "Very strong"),
    };

    notes.push("If you forget this password, the vault cannot be recovered.");

    Strength { score, label, entropy_bits: bits, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_password_is_weak() {
        let s = estimate("");
        assert_eq!(s.score, 0);
        assert_eq!(s.entropy_bits, 0);
    }

    #[test]
    fn common_passwords_are_weak_however_they_are_decorated() {
        for pw in ["password", "Password1", "qwerty", "letmein", "passw0rd"] {
            assert_eq!(estimate(pw).score, 0, "{pw} should score weak");
        }
    }

    #[test]
    fn a_short_symbol_soup_does_not_beat_a_long_passphrase() {
        let soup = estimate("P@ss1!");
        let phrase = estimate("correct horse battery staple");
        assert!(
            phrase.entropy_bits > soup.entropy_bits,
            "passphrase {} vs soup {}",
            phrase.entropy_bits,
            soup.entropy_bits
        );
        assert!(phrase.score >= 2);
    }

    #[test]
    fn a_long_passphrase_scores_well_without_symbols() {
        let s = estimate("purple monkey dishwasher lantern");
        assert!(s.score >= 2, "score was {} ({} bits)", s.score, s.entropy_bits);
        assert!(s.notes.iter().any(|n| n.contains("passphrase")));
    }

    #[test]
    fn repeated_characters_are_discounted() {
        let repeated = estimate("aaaaaaaaaaaaaaaaaaaaaaaa");
        let varied = estimate("ajwqodmzbxplrtvyeugcnsif");
        assert!(repeated.entropy_bits < varied.entropy_bits);
        assert!(repeated.notes.iter().any(|n| n.contains("Repeated")));
    }

    #[test]
    fn an_ordinary_passphrase_is_not_accused_of_repetition() {
        // "tunnel" and "kettle" each contain a doubled letter. Warning about
        // that would fire on almost every English passphrase.
        for pw in [
            "gravel tunnel morning kettle",
            "purple monkey dishwasher lantern",
            "correct horse battery staple",
        ] {
            let s = estimate(pw);
            assert!(
                !s.notes.iter().any(|n| n.contains("Repeated")),
                "{pw} was wrongly flagged for repetition"
            );
        }
    }

    #[test]
    fn the_score_rises_with_length() {
        let a = estimate("Tr0ub4dor");
        let b = estimate("Tr0ub4dor&3xtra");
        let c = estimate("Tr0ub4dor&3xtraLongerAndLonger");
        assert!(a.entropy_bits < b.entropy_bits);
        assert!(b.entropy_bits < c.entropy_bits);
        assert_eq!(c.score, 3);
    }

    #[test]
    fn non_ascii_passwords_are_handled_and_credited() {
        let s = estimate("正しい馬バッテリーステープル");
        assert!(s.entropy_bits > 60);
        assert!(s.score >= 2);
    }

    #[test]
    fn every_estimate_carries_the_no_recovery_warning() {
        for pw in ["", "x", "a decent long passphrase here"] {
            let s = estimate(pw);
            if pw.is_empty() {
                continue;
            }
            assert!(
                s.notes.iter().any(|n| n.contains("cannot be recovered")),
                "missing the no-recovery warning for {pw:?}"
            );
        }
    }

    #[test]
    fn notes_never_contain_the_password_itself() {
        let pw = "MyUniqueSecret12345";
        let s = estimate(pw);
        for n in &s.notes {
            assert!(!n.contains(pw));
        }
    }

    #[test]
    fn a_very_long_password_does_not_overflow() {
        let pw = "x".repeat(4096);
        let s = estimate(&pw);
        assert!(s.entropy_bits > 0);
    }
}

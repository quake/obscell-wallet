use ckb_hash::blake2b_256;
use secp256k1::{PublicKey, Scalar, SecretKey, ecdh::SharedSecret};
use sha2::{Digest, Sha256};

/// Generate an ephemeral keypair and derive the stealth public key.
///
/// Returns (ephemeral_pubkey, stealth_pubkey).
pub fn generate_ephemeral_key(
    view_pub: &PublicKey,
    spend_pub: &PublicKey,
) -> (PublicKey, PublicKey) {
    let mut rng = rand::rngs::OsRng;
    loop {
        let eph_secret = SecretKey::new(&mut rng);
        let eph_pub = PublicKey::from_secret_key_global(&eph_secret);
        let shared = SharedSecret::new(view_pub, &eph_secret);

        if let Ok(hashed_key) = hash_shared_to_secret(&shared) {
            let tweaked = PublicKey::from_secret_key_global(&hashed_key);
            let stealth_pub = spend_pub.combine(&tweaked).expect("combine ok");
            return (eph_pub, stealth_pub);
        }
    }
}

/// Check if a stealth script args matches this wallet's keys.
///
/// Returns true if the cell belongs to this wallet.
pub fn matches_key(
    stealth_script_args: &[u8],
    view_key: &SecretKey,
    spend_pub: &PublicKey,
) -> bool {
    if stealth_script_args.len() != 53 {
        return false;
    }

    if let Ok(eph_pub) = PublicKey::from_slice(&stealth_script_args[0..33]) {
        let shared = SharedSecret::new(&eph_pub, view_key);
        if let Ok(hashed_key) = hash_shared_to_secret(&shared)
            && let Ok(stealth_pub) =
                spend_pub.combine(&PublicKey::from_secret_key_global(&hashed_key))
        {
            return blake2b_256(stealth_pub.serialize())[0..20] == stealth_script_args[33..53];
        }
    }

    false
}

/// Derive the stealth secret key for signing.
///
/// Given a stealth script args and the wallet's keys, derive the secret key
/// that can sign for this stealth address.
pub fn derive_stealth_secret(
    stealth_script_args: &[u8],
    view_key: &SecretKey,
    spend_key: &SecretKey,
) -> Option<SecretKey> {
    if stealth_script_args.len() != 53 {
        return None;
    }

    let eph_pub = PublicKey::from_slice(&stealth_script_args[0..33]).ok()?;
    let shared = SharedSecret::new(&eph_pub, view_key);
    let hashed_key = hash_shared_to_secret(&shared).ok()?;

    let scalar = Scalar::from_be_bytes(hashed_key.secret_bytes()).ok()?;
    let stealth_secret = spend_key.add_tweak(&scalar).ok()?;

    Some(stealth_secret)
}

/// Hash a shared secret to derive a secret key.
pub fn hash_shared_to_secret(shared: &SharedSecret) -> Result<SecretKey, secp256k1::Error> {
    let mut hasher = Sha256::new();
    hasher.update(shared.secret_bytes());
    let hash = hasher.finalize();
    SecretKey::from_slice(&hash)
}

/// Format a u64 as CKB with 8 decimal places.
pub fn format_u64_8dec(x: u64) -> String {
    let int_part = x / 100_000_000;
    let frac_part = x % 100_000_000;
    format!("{}.{:08}", int_part, frac_part)
}

/// Parse a CKB amount string (with decimal point) to u64 shannons.
pub fn parse_8dec_to_u64(s: &str) -> Option<u64> {
    let mut parts = s.split('.');
    let int = parts.next()?;
    let frac = parts.next().unwrap_or("");

    if parts.next().is_some() || frac.len() > 8 {
        return None;
    }

    let frac_padded = format!("{:0<8}", frac);
    format!("{}{}", int, frac_padded).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_key_generation() {
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::rngs::OsRng;

        let view_secret = SecretKey::new(&mut rng);
        let spend_secret = SecretKey::new(&mut rng);
        let view_pub = PublicKey::from_secret_key(&secp, &view_secret);
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);

        let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);

        // Verify we can derive the stealth secret from the ephemeral pubkey
        let shared = SharedSecret::new(&eph_pub, &view_secret);
        let hashed = hash_shared_to_secret(&shared).unwrap();
        let scalar = Scalar::from_be_bytes(hashed.secret_bytes()).unwrap();
        let derived_secret = spend_secret.add_tweak(&scalar).unwrap();
        let derived_pub = PublicKey::from_secret_key(&secp, &derived_secret);

        assert_eq!(stealth_pub, derived_pub);
    }

    #[test]
    fn test_matches_key() {
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::rngs::OsRng;

        let view_secret = SecretKey::new(&mut rng);
        let spend_secret = SecretKey::new(&mut rng);
        let view_pub = PublicKey::from_secret_key(&secp, &view_secret);
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);

        let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);
        let pubkey_hash = blake2b_256(stealth_pub.serialize());

        let script_args = [eph_pub.serialize().as_slice(), &pubkey_hash[0..20]].concat();

        assert!(matches_key(&script_args, &view_secret, &spend_pub));
    }

    #[test]
    fn test_format_parse_ckb() {
        assert_eq!(format_u64_8dec(100_000_000), "1.00000000");
        assert_eq!(format_u64_8dec(123_456_789), "1.23456789");
        assert_eq!(format_u64_8dec(0), "0.00000000");

        assert_eq!(parse_8dec_to_u64("1.0"), Some(100_000_000));
        assert_eq!(parse_8dec_to_u64("1.23456789"), Some(123_456_789));
        assert_eq!(parse_8dec_to_u64("0"), Some(0));
    }
}

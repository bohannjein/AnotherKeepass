//! Bitwarden/Vaultwarden key handling: master key (PBKDF2 / Argon2id), server password
//! hash, HKDF stretch, EncStrings (type 0 / 2 AES-CBC(+HMAC), type 4 RSA-OAEP for org keys).

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kdf {
    /// 0 = PBKDF2-SHA256, 1 = Argon2id
    pub kind: u8,
    pub iterations: u32,
    /// Argon2: MiB
    pub memory: u32,
    pub parallelism: u32,
}

/// Symmetric key: AES-256 key + HMAC key (no MAC key only for legacy type-0 strings).
#[derive(Clone)]
pub struct SymKey {
    pub enc: Zeroizing<[u8; 32]>,
    pub mac: Option<Zeroizing<[u8; 32]>>,
}

impl SymKey {
    /// 64 bytes: enc || mac (user, organization and item keys)
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 64 {
            return Err(format!("bw_key_len:{}", b.len()));
        }
        let (mut enc, mut mac) = ([0u8; 32], [0u8; 32]);
        enc.copy_from_slice(&b[..32]);
        mac.copy_from_slice(&b[32..]);
        Ok(Self { enc: Zeroizing::new(enc), mac: Some(Zeroizing::new(mac)) })
    }
}

/// Bitwarden's minimums (and sane maximums): a server must not be able to make the password
/// hash cheap to brute-force, nor make us burn all memory.
pub fn check_kdf(k: &Kdf) -> Result<(), String> {
    #[cfg(not(test))]
    let min_pbkdf2 = 100_000;
    #[cfg(test)]
    let min_pbkdf2 = 5_000;
    let ok = match k.kind {
        0 => (min_pbkdf2..=5_000_000).contains(&k.iterations),
        1 => (2..=20).contains(&k.iterations) && (16..=1024).contains(&k.memory) && (1..=16).contains(&k.parallelism),
        _ => false,
    };
    if ok { Ok(()) } else { Err("bw:kdf_insecure".into()) }
}

/// Strength order to notice a server lowering the settings of a known account.
pub fn kdf_weaker(new: &Kdf, old: &Kdf) -> bool {
    new.kind == old.kind && (new.iterations < old.iterations || (new.kind == 1 && (new.memory < old.memory)))
}

/// Master key from password and email (the salt is the trimmed, lower-cased email).
pub fn master_key(password: &str, email: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, String> {
    check_kdf(kdf)?;
    let salt = email.trim().to_lowercase();
    let mut out = Zeroizing::new([0u8; 32]);
    match kdf.kind {
        0 => pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), kdf.iterations.max(1), out.as_mut()),
        1 => {
            let salt = Sha256::digest(salt.as_bytes());
            let config = argon2::Config {
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::Version13,
                mem_cost: kdf.memory.max(1) * 1024,
                time_cost: kdf.iterations.max(1),
                lanes: kdf.parallelism.max(1),
                hash_length: 32,
                ..argon2::Config::default()
            };
            let h = argon2::hash_raw(password.as_bytes(), &salt, &config).map_err(|e| format!("bw_kdf:{e}"))?;
            out.copy_from_slice(&h);
        }
        k => return Err(format!("bw_kdf_unknown:{k}")),
    }
    Ok(out)
}

/// What the server checks at login: one more PBKDF2 round of the master key over the password.
pub fn server_hash(master: &[u8; 32], password: &str) -> String {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(master, password.as_bytes(), 1, &mut out);
    B64.encode(out)
}

/// Stretched master key (HKDF-Expand "enc"/"mac") that decrypts the user key.
pub fn stretch(master: &[u8; 32]) -> SymKey {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(master).expect("32 byte prk");
    let (mut enc, mut mac) = ([0u8; 32], [0u8; 32]);
    hk.expand(b"enc", &mut enc).expect("32 bytes");
    hk.expand(b"mac", &mut mac).expect("32 bytes");
    SymKey { enc: Zeroizing::new(enc), mac: Some(Zeroizing::new(mac)) }
}

/// The protected user key: type 2 with the stretched master key, legacy type 0 with the master key itself.
pub fn decrypt_user_key(protected: &str, master: &[u8; 32]) -> Result<SymKey, String> {
    let key = if protected.starts_with("0.") { SymKey { enc: Zeroizing::new(*master), mac: None } } else { stretch(master) };
    let raw = Zeroizing::new(decrypt(protected, &key).map_err(|_| "wrong_key".to_string())?);
    SymKey::from_bytes(&raw)
}

fn parts(s: &str) -> Result<(u8, Vec<Vec<u8>>), String> {
    let (t, rest) = s.split_once('.').ok_or("bw_enc_format")?;
    let t: u8 = t.parse().map_err(|_| "bw_enc_format")?;
    let p = rest.split('|').map(|x| B64.decode(x).map_err(|_| "bw_enc_format".to_string())).collect::<Result<Vec<_>, _>>()?;
    Ok((t, p))
}

pub fn decrypt(s: &str, key: &SymKey) -> Result<Vec<u8>, String> {
    let (t, p) = parts(s)?;
    let (iv, data) = match (t, p.as_slice()) {
        // unauthenticated CBC only for the legacy protected user key (key without MAC part);
        // otherwise a server could flip bits in any value (downgrade attack)
        (0, [iv, data]) if key.mac.is_none() => (iv, data),
        (2, [iv, data, mac]) => {
            let mk = key.mac.as_ref().ok_or("bw_no_mac_key")?;
            let mut m = <HmacSha256 as Mac>::new_from_slice(mk.as_ref()).map_err(|_| "bw_mac")?;
            m.update(iv);
            m.update(data);
            m.verify_slice(mac).map_err(|_| "bw_mac".to_string())?;
            (iv, data)
        }
        _ => return Err(format!("bw_enc_type:{t}")),
    };
    let iv: [u8; 16] = iv.as_slice().try_into().map_err(|_| "bw_iv")?;
    let mut buf = data.clone();
    let n = Aes256CbcDec::new(key.enc.as_ref().into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "bw_decrypt".to_string())?
        .len();
    buf.truncate(n);
    Ok(buf)
}

pub fn decrypt_str(s: &str, key: &SymKey) -> Result<String, String> {
    String::from_utf8(decrypt(s, key)?).map_err(|_| "bw_utf8".into())
}

/// Type-2 EncString (random IV, AES-256-CBC, HMAC-SHA256 over iv||ciphertext).
pub fn encrypt(data: &[u8], key: &SymKey) -> String {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let mut buf = vec![0u8; data.len() + 16];
    buf[..data.len()].copy_from_slice(data);
    let n = Aes256CbcEnc::new(key.enc.as_ref().into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .expect("buffer has room for padding")
        .len();
    buf.truncate(n);
    let mac_key: &[u8] = match &key.mac {
        Some(k) => &k[..],
        None => &[0u8; 32],
    };
    let mut m = <HmacSha256 as Mac>::new_from_slice(mac_key).expect("hmac key");
    m.update(&iv);
    m.update(&buf);
    format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&buf), B64.encode(m.finalize().into_bytes()))
}

/// Organization keys come RSA-OAEP(SHA-1) encrypted to the user's private key (type 4).
pub fn decrypt_rsa(s: &str, private: &rsa::RsaPrivateKey) -> Result<Vec<u8>, String> {
    let (t, p) = parts(s)?;
    match (t, p.as_slice()) {
        (4, [data]) | (6, [data, _]) => private.decrypt(rsa::Oaep::new::<sha1::Sha1>(), data).map_err(|_| "bw_rsa".into()),
        (3, [data]) | (5, [data, _]) => private.decrypt(rsa::Oaep::new::<Sha256>(), data).map_err(|_| "bw_rsa".into()),
        _ => Err(format!("bw_enc_type:{t}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // vectors from the official Bitwarden SDK tests (bitwarden-crypto master_key.rs)
    #[test]
    fn kdf_vectors() {
        let kdf = Kdf { kind: 0, iterations: 100_000, memory: 0, parallelism: 0 };
        for email in ["test@bitwarden.com", "TEST@bitwarden.com", " test@bitwarden.com"] {
            let mk = master_key("asdfasdf", email, &kdf).unwrap();
            assert_eq!(server_hash(&mk, "asdfasdf"), "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=");
        }
        let kdf = Kdf { kind: 1, iterations: 4, memory: 32, parallelism: 2 };
        let mk = master_key("asdfasdf", "test_salt", &kdf).unwrap();
        assert_eq!(server_hash(&mk, "asdfasdf"), "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ=");
    }

    #[test]
    fn legacy_user_key_vector() {
        let kdf = Kdf { kind: 0, iterations: 600_000, memory: 0, parallelism: 0 };
        let mk = master_key("asdfasdfasdf", "legacy@bitwarden.com", &kdf).unwrap();
        let key = decrypt_user_key("0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=", &mk).unwrap();
        assert_eq!(key.enc.as_ref()[..4], [12, 95, 151, 203]);
        assert_eq!(key.mac.as_ref().unwrap().as_ref()[..4], [186, 215, 234, 137]);
    }

    #[test]
    fn type2_roundtrip_and_tamper() {
        let mk = [7u8; 32];
        let stretched = stretch(&mk);
        let mut user = [0u8; 64];
        OsRng.fill_bytes(&mut user);
        let protected = encrypt(&user, &stretched);
        let key = decrypt_user_key(&protected, &mk).unwrap();
        assert_eq!(key.enc.as_ref(), &user[..32]);
        let s = encrypt("hällo wörld".as_bytes(), &key);
        assert_eq!(decrypt_str(&s, &key).unwrap(), "hällo wörld");
        assert_eq!(decrypt_str(&encrypt(b"", &key), &key).unwrap(), "");
        // a changed ciphertext must fail the MAC check
        let mut bad: Vec<String> = s.split('|').map(String::from).collect();
        bad[1] = B64.encode(b"0123456789abcdef");
        assert!(decrypt(&bad.join("|"), &key).is_err());
        assert_eq!(decrypt_user_key(&protected, &[8u8; 32]).err().as_deref(), Some("wrong_key"));
        // a type-0 string must not be accepted with a MAC-capable key (downgrade)
        let p: Vec<&str> = s.trim_start_matches("2.").split('|').collect();
        assert!(decrypt(&format!("0.{}|{}", p[0], p[1]), &key).is_err());
        assert!(check_kdf(&Kdf { kind: 0, iterations: 1, memory: 0, parallelism: 0 }).is_err());
        assert!(check_kdf(&Kdf { kind: 1, iterations: 3, memory: 1_000_000, parallelism: 4 }).is_err());
    }
}

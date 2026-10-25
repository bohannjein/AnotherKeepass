//! Passkeys (WebAuthn) for the KeePassXC-Browser extension. We act as a software authenticator:
//! the extension forwards navigator.credentials.create/get, we build the WebAuthn response.
//! Storage is KeePassXC's: KPEX_PASSKEY_* strings on the entry (private key as PKCS#8 PEM),
//! so passkeys move freely between AnotherKeepass and KeePassXC.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const PRIVATE_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
pub const FLAG_BE: &str = "KPEX_PASSKEY_FLAG_BE";
pub const FLAG_BS: &str = "KPEX_PASSKEY_FLAG_BS";
/// StrongBox and others store the credential id here
pub const GENERATED_USER_ID: &str = "KPEX_PASSKEY_GENERATED_USER_ID";
pub const DEFAULT_GROUP: &str = "KeePassXC-Browser Passkeys";

/// Same AAGUID as KeePassXC, so relying parties see one known authenticator.
const AAGUID: [u8; 16] = [0xfd, 0xb1, 0x41, 0xb2, 0x5d, 0x84, 0x44, 0x3e, 0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02];
const ES256: i64 = -7;
const EDDSA: i64 = -8;

// error codes of the protocol
pub const E_EXCLUDED: u32 = 21;
pub const E_CANCELED: u32 = 22;
pub const E_EMPTY_PUBLIC_KEY: u32 = 24;
pub const E_INVALID_URL: u32 = 25;
const E_ORIGIN_NOT_ALLOWED: u32 = 26;
const E_DOMAIN_NOT_VALID: u32 = 27;
const E_RPID_MISMATCH: u32 = 28;
const E_NO_ALGORITHMS: u32 = 29;
pub const E_UNKNOWN: u32 = 31;
const E_CHALLENGE: u32 = 32;
const E_USER_ID: u32 = 33;

pub fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// The extension and KeePassXC use unpadded base64url; tolerate standard base64 too.
pub fn from_b64(s: &str) -> Option<Vec<u8>> {
    let t = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(t).ok().or_else(|| STANDARD.decode(s.trim()).ok())
}

pub fn error(code: u32) -> Value {
    json!({ "errorCode": code })
}

// ---------------------------------------------------------------- origin / RP ID

/// https origins only (plus localhost when allowed, like KeePassXC's option).
pub fn origin_allowed(origin: &str, localhost: bool) -> bool {
    if origin.starts_with("https://") {
        return true;
    }
    if !localhost {
        return false;
    }
    url::Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_string()))
        .is_some_and(|h| h == "localhost" || h.ends_with(".localhost"))
}

fn effective_domain(origin: &str) -> Result<String, u32> {
    let u = url::Url::parse(origin).map_err(|_| E_ORIGIN_NOT_ALLOWED)?;
    match u.host() {
        Some(url::Host::Domain(d)) if !d.ends_with('.') => Ok(d.to_ascii_lowercase()),
        Some(_) => Err(E_DOMAIN_NOT_VALID), // IP addresses can't own passkeys
        None => Err(E_ORIGIN_NOT_ALLOWED),
    }
}

/// RP ID must be the page's domain or a parent domain of it, and never a public suffix
/// ("com", "co.uk", "github.io"): a passkey for those would be valid for every site below them.
fn rp_id(requested: Option<&str>, domain: &str) -> Result<String, u32> {
    let Some(rp) = requested.map(|r| r.trim().to_ascii_lowercase()).filter(|r| !r.is_empty()) else {
        return Ok(domain.to_string());
    };
    let public_suffix = rp != "localhost" && psl::suffix(rp.as_bytes()).is_some_and(|s| s.trim().as_bytes() == rp.as_bytes());
    if !public_suffix && (rp == domain || domain.ends_with(&format!(".{rp}"))) { Ok(rp) } else { Err(E_RPID_MISMATCH) }
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> String {
    // field order as the WebAuthn serialization spec wants it; values JSON-escaped (page input)
    let q = |s: &str| serde_json::Value::String(s.to_string()).to_string();
    format!(r#"{{"type":{},"challenge":{},"origin":{},"crossOrigin":false}}"#, q(kind), q(challenge), q(origin))
}

// ---------------------------------------------------------------- CBOR (only what WebAuthn needs)

fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}
fn cbor_int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 { cbor_head(out, 0, v as u64) } else { cbor_head(out, 1, (-1 - v) as u64) }
}
fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len() as u64);
    out.extend(b);
}
fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len() as u64);
    out.extend(s.as_bytes());
}

/// COSE public key, key order as KeePassXC writes it.
fn cose_key(alg: i64, x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    if alg == ES256 {
        cbor_head(&mut o, 5, 5);
        for (k, v) in [(1, 2), (3, ES256), (-1, 1)] {
            cbor_int(&mut o, k);
            cbor_int(&mut o, v);
        }
        cbor_int(&mut o, -2);
        cbor_bytes(&mut o, x);
        cbor_int(&mut o, -3);
        cbor_bytes(&mut o, y);
    } else {
        cbor_head(&mut o, 5, 4);
        for (k, v) in [(1, 1), (3, EDDSA), (-1, 6)] {
            cbor_int(&mut o, k);
            cbor_int(&mut o, v);
        }
        cbor_int(&mut o, -2);
        cbor_bytes(&mut o, x);
    }
    o
}

fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    cbor_head(&mut o, 5, 3);
    cbor_text(&mut o, "fmt");
    cbor_text(&mut o, "none");
    cbor_text(&mut o, "attStmt");
    cbor_head(&mut o, 5, 0);
    cbor_text(&mut o, "authData");
    cbor_bytes(&mut o, auth_data);
    o
}

// ---------------------------------------------------------------- keys

struct NewKey {
    alg: i64,
    cose: Vec<u8>,
    pem: String,
    spki: Vec<u8>,
}

fn new_key(alg: i64) -> Result<NewKey, u32> {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    if alg == ES256 {
        let sk = p256::SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        let point = p256::EncodedPoint::from(pk);
        let (x, y) = (point.x().ok_or(E_UNKNOWN)?.to_vec(), point.y().ok_or(E_UNKNOWN)?.to_vec());
        Ok(NewKey {
            alg,
            cose: cose_key(ES256, &x, &y),
            pem: sk.to_pkcs8_pem(LineEnding::LF).map_err(|_| E_UNKNOWN)?.to_string(),
            spki: pk.to_public_key_der().map_err(|_| E_UNKNOWN)?.as_bytes().to_vec(),
        })
    } else {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        Ok(NewKey {
            alg,
            cose: cose_key(EDDSA, pk.as_bytes(), &[]),
            pem: sk.to_pkcs8_pem(LineEnding::LF).map_err(|_| E_UNKNOWN)?.to_string(),
            spki: pk.to_public_key_der().map_err(|_| E_UNKNOWN)?.as_bytes().to_vec(),
        })
    }
}

/// Sign with a stored PKCS#8 key: ECDSA P-256 (DER signature), Ed25519, or RSA (keys from KeePassXC).
fn sign(pem: &str, data: &[u8]) -> Result<Vec<u8>, u32> {
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = sk.sign(data);
        return Ok(sig.to_der().as_bytes().to_vec());
    }
    if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
        use ed25519_dalek::Signer;
        return Ok(sk.sign(data).to_bytes().to_vec());
    }
    if let Ok(sk) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        let digest = Sha256::digest(data);
        return sk.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest).map_err(|_| E_UNKNOWN);
    }
    Err(E_UNKNOWN)
}

/// authenticatorData: rpIdHash | flags | counter (always 0) | [attested credential data]
fn auth_data(rp: &str, be: bool, bs: bool, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut flags = 0x01 | 0x04; // UP, UV
    if be {
        flags |= 0x08;
    }
    if bs {
        flags |= 0x10;
    }
    if attested.is_some() {
        flags |= 0x40;
    }
    let mut d = Sha256::digest(rp.as_bytes()).to_vec();
    d.push(flags);
    d.extend([0, 0, 0, 0]);
    if let Some((cred, cose)) = attested {
        d.extend(AAGUID);
        d.extend((cred.len() as u16).to_be_bytes());
        d.extend(cred);
        d.extend(cose);
    }
    d
}

// ---------------------------------------------------------------- create / get

/// Checked request for navigator.credentials.create.
pub struct Registration {
    pub rp_id: String,
    pub rp_name: String,
    pub username: String,
    pub user_handle: String,
    pub exclude: Vec<String>,
    alg: i64,
    challenge: String,
    origin: String,
}

pub fn check_create(pk: &Value, origin: &str) -> Result<Registration, u32> {
    let challenge = pk["challenge"].as_str().unwrap_or_default();
    if challenge.len() < 16 {
        return Err(E_CHALLENGE);
    }
    let user_handle = pk["user"]["id"].as_str().unwrap_or_default().to_string();
    if !from_b64(&user_handle).is_some_and(|u| (1..=64).contains(&u.len())) {
        return Err(E_USER_ID);
    }
    let domain = effective_domain(origin)?;
    let rp_id = rp_id(pk["rp"]["id"].as_str(), &domain)?;
    // first supported algorithm the site lists (empty list = defaults, ES256 first)
    let algs: Vec<i64> = pk["pubKeyCredParams"]
        .as_array()
        .map(|a| a.iter().filter(|p| p["type"] == "public-key").filter_map(|p| p["alg"].as_i64()).collect())
        .unwrap_or_default();
    let alg = if algs.is_empty() { ES256 } else { *algs.iter().find(|a| [ES256, EDDSA].contains(a)).ok_or(E_NO_ALGORITHMS)? };
    Ok(Registration {
        rp_name: pk["rp"]["name"].as_str().unwrap_or(&rp_id).to_string(),
        rp_id,
        username: pk["user"]["name"].as_str().unwrap_or_default().to_string(),
        user_handle,
        exclude: pk["excludeCredentials"]
            .as_array()
            .map(|a| a.iter().filter_map(|c| c["id"].as_str().map(String::from)).collect())
            .unwrap_or_default(),
        alg,
        challenge: challenge.to_string(),
        origin: origin.to_string(),
    })
}

/// New credential → (PublicKeyCredential JSON, credential id, private key PEM).
pub fn create(r: &Registration, attachment: Option<&str>) -> Result<(Value, String, String), u32> {
    let key = new_key(r.alg)?;
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    let cred_id = b64url(&id);
    let attested = auth_data(&r.rp_id, true, true, Some((&id, &key.cose)));
    let plain = auth_data(&r.rp_id, true, true, None);
    let client = client_data("webauthn.create", &r.challenge, &r.origin);
    let credential = json!({
        "authenticatorAttachment": attachment.unwrap_or("platform"),
        "id": cred_id,
        "type": "public-key",
        "response": {
            "attestationObject": b64url(&attestation_object(&attested)),
            "clientDataJSON": b64url(client.as_bytes()),
            "clientExtensionResults": {},
            "authenticatorData": b64url(&plain),
            "publicKey": b64url(&key.spki),
            "publicKeyAlgorithm": key.alg,
        },
    });
    Ok((credential, cred_id, key.pem))
}

/// Checked request for navigator.credentials.get → (rp id, allowed credential ids).
pub fn check_get(pk: &Value, origin: &str) -> Result<(String, Vec<String>), u32> {
    let domain = effective_domain(origin)?;
    let rp = rp_id(pk["rpId"].as_str(), &domain)?;
    let allowed = pk["allowCredentials"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c["type"] == "public-key")
                .filter(|c| {
                    c["transports"].as_array().is_none_or(|t| {
                        t.is_empty() || t.iter().any(|x| ["internal", "nfc", "usb"].contains(&x.as_str().unwrap_or_default()))
                    })
                })
                .filter_map(|c| c["id"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok((rp, allowed))
}

/// Assertion for a stored passkey.
#[allow(clippy::too_many_arguments)] // mirrors the WebAuthn assertion inputs one to one
pub fn assert(pk: &Value, origin: &str, rp: &str, cred_id: &str, user_handle: &str, pem: &str, be: bool, bs: bool) -> Result<Value, u32> {
    let data = auth_data(rp, be, bs, None);
    let client = client_data("webauthn.get", pk["challenge"].as_str().unwrap_or_default(), origin);
    let mut signed = data.clone();
    signed.extend(Sha256::digest(client.as_bytes()));
    let signature = sign(pem, &signed)?;
    Ok(json!({
        "authenticatorAttachment": "platform",
        "id": cred_id,
        "type": "public-key",
        "response": {
            "authenticatorData": b64url(&data),
            "clientDataJSON": b64url(client.as_bytes()),
            "clientExtensionResults": {},
            "signature": b64url(&signature),
            "userHandle": user_handle,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Value {
        json!({
            "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "rp": { "id": "example.com", "name": "Example" },
            "user": { "id": "dXNlcjE", "name": "alice" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -257 }, { "type": "public-key", "alg": -7 }],
        })
    }

    #[test]
    fn rp_rules() {
        assert_eq!(rp_id(Some("example.com"), "login.example.com"), Ok("example.com".into()));
        assert_eq!(rp_id(None, "login.example.com"), Ok("login.example.com".into()));
        assert_eq!(rp_id(Some("com"), "example.com"), Err(E_RPID_MISMATCH));
        assert_eq!(rp_id(Some("evil.com"), "example.com"), Err(E_RPID_MISMATCH));
        assert_eq!(rp_id(Some("co.uk"), "shop.example.co.uk"), Err(E_RPID_MISMATCH));
        assert_eq!(rp_id(Some("github.io"), "me.github.io"), Err(E_RPID_MISMATCH));
        assert_eq!(rp_id(Some("example.co.uk"), "shop.example.co.uk"), Ok("example.co.uk".into()));
        assert_eq!(rp_id(Some("me.github.io"), "me.github.io"), Ok("me.github.io".into()));
        assert_eq!(rp_id(Some("localhost"), "localhost"), Ok("localhost".into()));
        assert_eq!(effective_domain("https://10.0.0.1"), Err(E_DOMAIN_NOT_VALID));
        assert!(origin_allowed("https://a.com", false) && !origin_allowed("http://localhost:3000", false));
        assert!(origin_allowed("http://localhost:3000", true));
    }

    #[test]
    fn register_then_sign_verifies() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use p256::pkcs8::DecodePublicKey;
        let reg = check_create(&options(), "https://login.example.com").unwrap();
        assert_eq!(reg.alg, ES256);
        let (cred, id, pem) = create(&reg, None).unwrap();
        assert_eq!(cred["id"], id);
        let att = from_b64(cred["response"]["attestationObject"].as_str().unwrap()).unwrap();
        assert_eq!(att[0], 0xa3); // map of 3
        // assertion signature checks out against the published SPKI key
        let spki = from_b64(cred["response"]["publicKey"].as_str().unwrap()).unwrap();
        let vk = VerifyingKey::from_public_key_der(&spki).unwrap();
        let get = json!({ "challenge": "BBBBBBBBBBBBBBBBBBBBBBBB", "rpId": "example.com" });
        let (rp, _) = check_get(&get, "https://login.example.com").unwrap();
        let a = assert(&get, "https://login.example.com", &rp, &id, "dXNlcjE", &pem, true, true).unwrap();
        let mut signed = from_b64(a["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        signed.extend(Sha256::digest(from_b64(a["response"]["clientDataJSON"].as_str().unwrap()).unwrap()));
        let sig = Signature::from_der(&from_b64(a["response"]["signature"].as_str().unwrap()).unwrap()).unwrap();
        assert!(vk.verify(&signed, &sig).is_ok());
        assert_eq!(signed[32], 0x1d); // UP UV BE BS
    }

    #[test]
    fn ed25519_and_errors() {
        let mut o = options();
        o["pubKeyCredParams"] = json!([{ "type": "public-key", "alg": -8 }]);
        let reg = check_create(&o, "https://example.com").unwrap();
        let (_, _, pem) = create(&reg, None).unwrap();
        assert_eq!(sign(&pem, b"x").unwrap().len(), 64);
        o["pubKeyCredParams"] = json!([{ "type": "public-key", "alg": -257 }]);
        assert_eq!(check_create(&o, "https://example.com").err(), Some(E_NO_ALGORITHMS));
        o["challenge"] = json!("short");
        assert_eq!(check_create(&o, "https://example.com").err(), Some(E_CHALLENGE));
    }
}

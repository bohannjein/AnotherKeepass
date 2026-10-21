//! Vaultwarden HTTP API: prelogin, token (password grant + 2FA + remember token, refresh),
//! sync, cipher and folder writes.

use std::time::Duration;

use serde_json::{json, Value};

use super::crypto::Kdf;

const CLIENT: &str = "desktop";
/// Bitwarden device type 6 = Windows desktop
const DEVICE_TYPE: &str = "6";

pub struct Session {
    pub server: String,
    pub access: String,
    pub refresh: String,
}

#[derive(Debug, PartialEq)]
pub enum LoginError {
    /// second factor needed: provider ids (0 = authenticator app, 1 = email, …)
    TwoFactor(Vec<u8>),
    WrongPassword,
    /// server unreachable – the offline cache may help
    Offline(String),
    Other(String),
}

fn agent() -> ureq::Agent {
    // Windows certificate store (company CAs) and proxy settings from the environment
    ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).user_agent("AnotherKeepass").try_proxy_from_env(true).build()
}

pub fn base(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

fn transport(e: ureq::Error) -> LoginError {
    match e {
        ureq::Error::Transport(t) => LoginError::Offline(t.to_string()),
        ureq::Error::Status(code, r) => LoginError::Other(format!("http {code}: {}", r.into_string().unwrap_or_default())),
    }
}

/// Key derivation settings of an account.
pub fn prelogin(server: &str, email: &str) -> Result<Kdf, LoginError> {
    let v: Value = agent()
        .post(&format!("{}/identity/accounts/prelogin", base(server)))
        .send_json(json!({ "email": email.trim() }))
        .map_err(transport)?
        .into_json()
        .map_err(|e| LoginError::Other(e.to_string()))?;
    let n = |k: &str| v.get(k).or_else(|| v.get(&capitalize(k))).and_then(Value::as_u64);
    Ok(Kdf {
        kind: n("kdf").unwrap_or(0) as u8,
        iterations: n("kdfIterations").unwrap_or(600_000) as u32,
        memory: n("kdfMemory").unwrap_or(64) as u32,
        parallelism: n("kdfParallelism").unwrap_or(4) as u32,
    })
}

fn capitalize(k: &str) -> String {
    let mut c = k.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// Case-insensitive JSON field (Bitwarden mixes PascalCase and camelCase).
pub fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    if let Some(x) = v.get(key) {
        return x;
    }
    v.as_object()
        .and_then(|o| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, x)| x))
        .unwrap_or(&Value::Null)
}

pub struct TokenResponse {
    pub session: Session,
    /// protected user key, protected RSA private key
    pub key: String,
    pub private_key: Option<String>,
    /// "remember this device" token for the next logins without 2FA
    pub remember: Option<String>,
}

/// Password grant. `second`: (provider, code); provider 5 = remember token.
pub fn login(
    server: &str,
    email: &str,
    hash: &str,
    device_id: &str,
    second: Option<(u8, &str)>,
) -> Result<TokenResponse, LoginError> {
    let provider = second.map(|(p, _)| p.to_string());
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "password"),
        ("username", email.trim()),
        ("password", hash),
        ("scope", "api offline_access"),
        ("client_id", CLIENT),
        ("deviceType", DEVICE_TYPE),
        ("deviceIdentifier", device_id),
        ("deviceName", "AnotherKeepass"),
    ];
    if let (Some((_, code)), Some(p)) = (second, provider.as_deref()) {
        form.extend([("twoFactorToken", code), ("twoFactorProvider", p), ("twoFactorRemember", "1")]);
    }
    let res = agent()
        .post(&format!("{}/identity/connect/token", base(server)))
        .set("Bitwarden-Client-Name", CLIENT)
        .set("Device-Type", DEVICE_TYPE)
        .send_form(&form);
    let v: Value = match res {
        Ok(r) => r.into_json().map_err(|e| LoginError::Other(e.to_string()))?,
        Err(ureq::Error::Status(_, r)) => {
            let v: Value = r.into_json().unwrap_or(Value::Null);
            let providers = field(&v, "TwoFactorProviders");
            if let Some(list) = providers.as_array().filter(|l| !l.is_empty()) {
                let ids = list.iter().filter_map(|p| p.as_u64().or_else(|| p.as_str()?.parse().ok())).map(|p| p as u8).collect();
                return Err(LoginError::TwoFactor(ids));
            }
            let msg = field(&v, "error_description").as_str().or(field(&v, "message").as_str()).unwrap_or("login failed").to_string();
            return Err(if msg.to_lowercase().contains("password") { LoginError::WrongPassword } else { LoginError::Other(msg) });
        }
        Err(e) => return Err(transport(e)),
    };
    let s = |k: &str| field(&v, k).as_str().map(String::from);
    Ok(TokenResponse {
        session: Session { server: base(server), access: s("access_token").unwrap_or_default(), refresh: s("refresh_token").unwrap_or_default() },
        key: s("Key").ok_or_else(|| LoginError::Other("no key in token response".into()))?,
        private_key: s("PrivateKey"),
        remember: s("TwoFactorToken"),
    })
}

/// Ask the server to mail a login code (email 2FA).
pub fn send_email_code(server: &str, email: &str, hash: &str, device_id: &str) -> Result<(), String> {
    agent()
        .post(&format!("{}/api/two-factor/send-email-login", base(server)))
        .send_json(json!({ "email": email.trim(), "masterPasswordHash": hash, "deviceIdentifier": device_id }))
        .map(|_| ())
        .map_err(|e| format!("bw:{e}"))
}

impl Session {
    fn refresh(&mut self) -> Result<(), String> {
        let v: Value = agent()
            .post(&format!("{}/identity/connect/token", self.server))
            .send_form(&[("grant_type", "refresh_token"), ("client_id", CLIENT), ("refresh_token", &self.refresh)])
            .map_err(|e| format!("bw:{e}"))?
            .into_json()
            .map_err(|e| format!("bw:{e}"))?;
        self.access = field(&v, "access_token").as_str().unwrap_or_default().to_string();
        if let Some(r) = field(&v, "refresh_token").as_str() {
            self.refresh = r.to_string();
        }
        Ok(())
    }

    /// Authorized request; an expired access token is refreshed once.
    fn call(&mut self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        for attempt in 0..2 {
            let req = agent().request(method, &format!("{}/api{}", self.server, path)).set("Authorization", &format!("Bearer {}", self.access));
            let res = match body {
                Some(b) => req.send_json(b.clone()),
                None => req.call(),
            };
            match res {
                Ok(r) => return Ok(r.into_json().unwrap_or(Value::Null)),
                Err(ureq::Error::Status(401, _)) if attempt == 0 => self.refresh()?,
                Err(ureq::Error::Status(code, r)) => {
                    let text = r.into_string().unwrap_or_default();
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let msg = field(&v, "message").as_str().map(String::from).unwrap_or(text);
                    return Err(format!("bw:{code}: {msg}"));
                }
                Err(e) => return Err(format!("offline:{e}")),
            }
        }
        Err("bw:unauthorized".into())
    }

    pub fn sync(&mut self) -> Result<Value, String> {
        self.call("GET", "/sync?excludeDomains=true", None)
    }
    pub fn create_cipher(&mut self, body: &Value) -> Result<Value, String> {
        self.call("POST", "/ciphers", Some(body))
    }
    pub fn update_cipher(&mut self, id: &str, body: &Value) -> Result<Value, String> {
        self.call("PUT", &format!("/ciphers/{id}"), Some(body))
    }
    pub fn trash_cipher(&mut self, id: &str) -> Result<(), String> {
        self.call("PUT", &format!("/ciphers/{id}/delete"), None).map(|_| ())
    }
    pub fn restore_cipher(&mut self, id: &str) -> Result<(), String> {
        self.call("PUT", &format!("/ciphers/{id}/restore"), None).map(|_| ())
    }
    pub fn delete_cipher(&mut self, id: &str) -> Result<(), String> {
        self.call("DELETE", &format!("/ciphers/{id}"), None).map(|_| ())
    }
    pub fn create_folder(&mut self, name: &str) -> Result<String, String> {
        let v = self.call("POST", "/folders", Some(&json!({ "name": name })))?;
        field(&v, "id").as_str().map(String::from).ok_or_else(|| "bw:no folder id".into())
    }
    pub fn rename_folder(&mut self, id: &str, name: &str) -> Result<(), String> {
        self.call("PUT", &format!("/folders/{id}"), Some(&json!({ "name": name }))).map(|_| ())
    }
    pub fn delete_folder(&mut self, id: &str) -> Result<(), String> {
        self.call("DELETE", &format!("/folders/{id}"), None).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_case_fields() {
        let v = json!({ "Key": "a", "privateKey": "b" });
        assert_eq!(field(&v, "key"), "a");
        assert_eq!(field(&v, "PrivateKey"), "b");
        assert!(field(&v, "x").is_null());
        assert_eq!(base(" https://vault.example.com/ "), "https://vault.example.com");
    }
}

//! Capability tokens — short-lived, scoped, signed bearer credentials.
//!
//! v0.2.2 [`crate::tenant`] introduced always-on RBAC grants (operator,
//! admin, auditor, etc.). Capability tokens layer on top: a grant
//! authorises *what* a principal can do; a token authorises *one specific
//! action* the bearer can perform *for a short time window*. This is the
//! modern enterprise auth model — short-lived bearer tokens minted on
//! demand, dropped at the door.
//!
//! ## Why not JWT?
//!
//! JWT is fine but is a 3-blob (header, payload, signature) format with
//! a ton of vulnerable variants (`none` algorithm, weak HMAC, RSA padding
//! oracle). We ship a simpler, narrower contract:
//!
//!   `aeth.v1.<base64url(payload)>.<base64url(signature)>`
//!
//! - Payload is canonical JSON.
//! - Signature is HMAC-SHA-256 with a per-issuer secret.
//! - No algorithm-negotiation footgun (the algorithm is fixed by version).
//!
//! Tokens carry: `tenant`, `principal`, `permissions`, `expires_at`,
//! `issued_at`, `nonce`, `audience`, optional `tags`.
//!
//! ## What this gives you
//!
//! ```ignore
//! let issuer = TokenIssuer::new("ae-issuer-1", b"shared-secret");
//! let token = issuer.mint(TokenClaims {
//!     tenant: "FAB".into(),
//!     principal: "alice".into(),
//!     permissions: vec![Permission::SealAppend],
//!     expires_at: now + Duration::minutes(15),
//!     ...
//! })?;
//! // Send `token.encoded()` as Authorization: Bearer header.
//!
//! let verifier = TokenVerifier::new("ae-issuer-1", b"shared-secret");
//! let claims = verifier.verify(&token.encoded())?;
//! assert!(claims.has_permission(Permission::SealAppend));
//! ```

use crate::hashing::Hasher;
use crate::tenant::Permission;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashSet;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// TokenClaims
// =============================================================================

/// Canonical claim set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    /// Token version.
    pub v: u8,
    /// Token id (UUIDv7 for ordering).
    pub jti: Uuid,
    /// Issuer id.
    pub iss: String,
    /// Audience (the service that should accept this token).
    pub aud: String,
    /// Tenant.
    pub tenant: String,
    /// Principal.
    pub principal: String,
    /// Permissions granted by this token.
    pub permissions: Vec<Permission>,
    /// RFC 3339 issuance timestamp.
    pub iat: String,
    /// RFC 3339 expiration.
    pub exp: String,
    /// Single-use nonce (random).
    pub nonce: String,
    /// Optional free-form tags (e.g., `"session_id"`, `"ip"`).
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

impl TokenClaims {
    /// Builder.
    pub fn builder(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        tenant: impl Into<String>,
        principal: impl Into<String>,
    ) -> TokenClaimsBuilder {
        TokenClaimsBuilder {
            iss: issuer.into(),
            aud: audience.into(),
            tenant: tenant.into(),
            principal: principal.into(),
            permissions: Vec::new(),
            ttl: time::Duration::minutes(15),
            tags: BTreeMap::new(),
        }
    }

    /// `true` if this token grants the given permission.
    pub fn has_permission(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }

    /// Parse `exp` into an OffsetDateTime.
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::parse(&self.exp, &time::format_description::well_known::Rfc3339).ok()
    }

    /// Parse `iat`.
    pub fn issued_at(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::parse(&self.iat, &time::format_description::well_known::Rfc3339).ok()
    }

    /// `true` if `now > exp`.
    pub fn is_expired(&self) -> bool {
        match self.expires_at() {
            None => true,
            Some(e) => OffsetDateTime::now_utc() >= e,
        }
    }
}

/// Builder for [`TokenClaims`].
pub struct TokenClaimsBuilder {
    iss: String,
    aud: String,
    tenant: String,
    principal: String,
    permissions: Vec<Permission>,
    ttl: time::Duration,
    tags: BTreeMap<String, String>,
}

impl TokenClaimsBuilder {
    /// Add a permission.
    pub fn permission(mut self, p: Permission) -> Self {
        self.permissions.push(p);
        self
    }
    /// Set permissions.
    pub fn permissions(mut self, ps: Vec<Permission>) -> Self {
        self.permissions = ps;
        self
    }
    /// Set TTL (max validity).
    pub fn ttl(mut self, d: time::Duration) -> Self {
        self.ttl = d;
        self
    }
    /// Add a tag.
    pub fn tag(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.tags.insert(k.into(), v.into());
        self
    }
    /// Build.
    pub fn build(self) -> TokenClaims {
        let now = OffsetDateTime::now_utc();
        let iat = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let exp = (now + self.ttl)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let nonce = Uuid::now_v7().to_string();
        TokenClaims {
            v: 1,
            jti: Uuid::now_v7(),
            iss: self.iss,
            aud: self.aud,
            tenant: self.tenant,
            principal: self.principal,
            permissions: self.permissions,
            iat,
            exp,
            nonce,
            tags: self.tags,
        }
    }
}

// =============================================================================
// Encoded token
// =============================================================================

/// Encoded `aeth.v1.<payload>.<sig>` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedToken {
    encoded: String,
}

impl EncodedToken {
    /// Borrow the encoded string.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.encoded.len()
    }

    /// `true` if empty (degenerate).
    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }
}

// =============================================================================
// Encoding helpers (base64url, no padding)
// =============================================================================

fn b64_url_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b = &bytes[i..i + 3];
        out.push(CHARS[(b[0] >> 2) as usize] as char);
        out.push(CHARS[((b[0] & 0x03) << 4 | (b[1] >> 4)) as usize] as char);
        out.push(CHARS[((b[1] & 0x0f) << 2 | (b[2] >> 6)) as usize] as char);
        out.push(CHARS[(b[2] & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i];
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[((b0 & 0x03) << 4) as usize] as char);
    } else if rem == 2 {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[((b0 & 0x03) << 4 | (b1 >> 4)) as usize] as char);
        out.push(CHARS[((b1 & 0x0f) << 2) as usize] as char);
    }
    out
}

fn b64_url_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in bytes {
        let v = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue, // skip padding if present
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// =============================================================================
// HMAC-SHA-256 (hand-rolled — uses our Hasher::sha256)
// =============================================================================

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = Hasher::sha256(key).0;
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = Hasher::sha256(&inner).0;
    let mut outer = Vec::with_capacity(BLOCK_SIZE + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    Hasher::sha256(&outer).0
}

// =============================================================================
// TokenIssuer
// =============================================================================

/// Mints encoded tokens by signing claims with HMAC-SHA-256.
pub struct TokenIssuer {
    issuer_id: String,
    secret: Vec<u8>,
}

impl TokenIssuer {
    /// New issuer with a shared secret.
    pub fn new(issuer_id: impl Into<String>, secret: &[u8]) -> Self {
        Self {
            issuer_id: issuer_id.into(),
            secret: secret.to_vec(),
        }
    }

    /// Issuer id.
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Mint a token.
    pub fn mint(&self, claims: TokenClaims) -> SandboxResult<EncodedToken> {
        if claims.iss != self.issuer_id {
            return Err(SandboxError::Other(format!(
                "claim issuer {} does not match issuer {}",
                claims.iss, self.issuer_id
            )));
        }
        let payload_json = serde_json::to_vec(&claims)
            .map_err(|e| SandboxError::Other(format!("serialise claims: {e}")))?;
        let payload_b64 = b64_url_encode(&payload_json);
        let signing_input = format!("aeth.v1.{}", payload_b64);
        let sig = hmac_sha256(&self.secret, signing_input.as_bytes());
        let sig_b64 = b64_url_encode(&sig);
        let encoded = format!("{}.{}", signing_input, sig_b64);
        Ok(EncodedToken { encoded })
    }
}

// =============================================================================
// TokenVerifier
// =============================================================================

/// Verifies encoded tokens.
pub struct TokenVerifier {
    issuer_id: String,
    secret: Vec<u8>,
    /// Used-nonce ledger to prevent replay (in-memory).
    used_nonces: std::sync::Mutex<HashSet<String>>,
    /// Whether to reject already-seen nonces.
    reject_replays: bool,
}

impl TokenVerifier {
    /// New verifier.
    pub fn new(issuer_id: impl Into<String>, secret: &[u8]) -> Self {
        Self {
            issuer_id: issuer_id.into(),
            secret: secret.to_vec(),
            used_nonces: std::sync::Mutex::new(HashSet::new()),
            reject_replays: true,
        }
    }

    /// Disable nonce replay protection (for stateless verification).
    pub fn allow_replays(mut self) -> Self {
        self.reject_replays = false;
        self
    }

    /// Verify an encoded token, returning the claims.
    pub fn verify(&self, encoded: &str) -> SandboxResult<TokenClaims> {
        // Format: aeth.v1.<payload>.<sig>
        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 4 || parts[0] != "aeth" || parts[1] != "v1" {
            return Err(SandboxError::Other("malformed token format".into()));
        }
        let payload_b64 = parts[2];
        let sig_b64 = parts[3];
        // Verify signature.
        let expected_sig_input = format!("aeth.v1.{}", payload_b64);
        let expected_sig = hmac_sha256(&self.secret, expected_sig_input.as_bytes());
        let expected_sig_b64 = b64_url_encode(&expected_sig);
        if !constant_time_eq(sig_b64.as_bytes(), expected_sig_b64.as_bytes()) {
            return Err(SandboxError::Other("signature mismatch".into()));
        }
        let payload =
            b64_url_decode(payload_b64).ok_or_else(|| SandboxError::Other("bad payload b64".into()))?;
        let claims: TokenClaims = serde_json::from_slice(&payload)
            .map_err(|e| SandboxError::Other(format!("parse claims: {e}")))?;
        if claims.v != 1 {
            return Err(SandboxError::Other(format!(
                "unsupported token version: {}",
                claims.v
            )));
        }
        if claims.iss != self.issuer_id {
            return Err(SandboxError::Other(format!(
                "issuer mismatch: token={} verifier={}",
                claims.iss, self.issuer_id
            )));
        }
        if claims.is_expired() {
            return Err(SandboxError::Other("token expired".into()));
        }
        if self.reject_replays {
            let mut g = self
                .used_nonces
                .lock()
                .map_err(|_| SandboxError::Other("nonce ledger poisoned".into()))?;
            if !g.insert(claims.nonce.clone()) {
                return Err(SandboxError::Other("nonce already used (replay)".into()));
            }
        }
        Ok(claims)
    }

    /// Number of nonces seen so far.
    pub fn seen_nonce_count(&self) -> usize {
        self.used_nonces.lock().map(|g| g.len()).unwrap_or(0)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> TokenIssuer {
        TokenIssuer::new("aeth-issuer-1", b"shared-secret-32-bytes-or-more!!")
    }
    fn verifier() -> TokenVerifier {
        TokenVerifier::new("aeth-issuer-1", b"shared-secret-32-bytes-or-more!!")
    }

    fn claims() -> TokenClaims {
        TokenClaims::builder("aeth-issuer-1", "sandbox", "FAB", "alice")
            .permission(Permission::SealAppend)
            .ttl(time::Duration::minutes(5))
            .build()
    }

    #[test]
    fn b64_url_encode_decode_round_trip() {
        for input in [
            b"".as_ref(),
            b"A".as_ref(),
            b"AB".as_ref(),
            b"ABC".as_ref(),
            b"ABCD".as_ref(),
            b"hello world".as_ref(),
            &[0u8, 1, 2, 3, 0xff, 0xfe, 0xfd],
        ] {
            let encoded = b64_url_encode(input);
            let decoded = b64_url_decode(&encoded).unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn b64_url_encode_no_padding() {
        let s = b64_url_encode(b"AB"); // should produce no =
        assert!(!s.contains('='));
    }

    #[test]
    fn b64_url_decode_bad_chars() {
        assert!(b64_url_decode("@@@@").is_none());
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 1: key = 0x0b * 20, msg = "Hi There".
        let key = [0x0b; 20];
        let msg = b"Hi There";
        let mac = hmac_sha256(&key, msg);
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
        assert_eq!(mac.as_ref(), expected.as_slice());
    }

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"hello", b"hellos"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn issuer_mints_token() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        assert!(t.encoded().starts_with("aeth.v1."));
    }

    #[test]
    fn verifier_accepts_own_token() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        let v = verifier();
        let c = v.verify(t.encoded()).unwrap();
        assert_eq!(c.principal, "alice");
    }

    #[test]
    fn verifier_rejects_tampered_token() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        let v = verifier();
        // Flip a byte in the payload.
        let mut s = t.encoded().to_string();
        let mid = s.len() / 2;
        s.replace_range(mid..mid + 1, "X");
        assert!(v.verify(&s).is_err());
    }

    #[test]
    fn verifier_rejects_wrong_issuer() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        let v = TokenVerifier::new("other-issuer", b"shared-secret-32-bytes-or-more!!");
        assert!(v.verify(t.encoded()).is_err());
    }

    #[test]
    fn verifier_rejects_wrong_secret() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        let v = TokenVerifier::new("aeth-issuer-1", b"different-secret-32-bytes-or-more!");
        assert!(v.verify(t.encoded()).is_err());
    }

    #[test]
    fn verifier_rejects_expired_token() {
        let i = issuer();
        let mut c = claims();
        c.exp = (OffsetDateTime::now_utc() - time::Duration::minutes(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let t = i.mint(c).unwrap();
        let v = verifier();
        assert!(v.verify(t.encoded()).is_err());
    }

    #[test]
    fn verifier_rejects_malformed() {
        let v = verifier();
        assert!(v.verify("not.a.token.at.all").is_err());
        assert!(v.verify("aeth.v2.foo.bar").is_err());
        assert!(v.verify("foo.v1.bar.baz").is_err());
    }

    #[test]
    fn verifier_rejects_replay() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        let v = verifier();
        v.verify(t.encoded()).unwrap();
        let r = v.verify(t.encoded());
        assert!(r.is_err());
    }

    #[test]
    fn verifier_allow_replays_mode() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        let v = verifier().allow_replays();
        v.verify(t.encoded()).unwrap();
        v.verify(t.encoded()).unwrap();
    }

    #[test]
    fn verifier_seen_nonce_count() {
        let i = issuer();
        let v = verifier();
        for _ in 0..5 {
            let t = i.mint(claims()).unwrap();
            v.verify(t.encoded()).unwrap();
        }
        assert_eq!(v.seen_nonce_count(), 5);
    }

    #[test]
    fn token_claims_builder_includes_permissions() {
        let c = TokenClaims::builder("i", "s", "T", "P")
            .permission(Permission::SealAppend)
            .permission(Permission::SealRead)
            .build();
        assert_eq!(c.permissions.len(), 2);
        assert!(c.has_permission(Permission::SealAppend));
        assert!(c.has_permission(Permission::SealRead));
        assert!(!c.has_permission(Permission::TenantManage));
    }

    #[test]
    fn token_claims_default_ttl_15min() {
        let c = TokenClaims::builder("i", "s", "T", "P").build();
        let exp = c.expires_at().unwrap();
        let iat = c.issued_at().unwrap();
        let dur = exp - iat;
        assert!(dur.whole_minutes() >= 14 && dur.whole_minutes() <= 15);
    }

    #[test]
    fn token_claims_with_tags() {
        let c = TokenClaims::builder("i", "s", "T", "P")
            .tag("session", "s1")
            .tag("ip", "10.0.0.1")
            .build();
        assert_eq!(c.tags.len(), 2);
    }

    #[test]
    fn issuer_rejects_mismatched_iss_in_claims() {
        let i = issuer();
        let mut c = claims();
        c.iss = "wrong-issuer".into();
        let r = i.mint(c);
        assert!(r.is_err());
    }

    #[test]
    fn token_claims_serde_round_trip() {
        let c = claims();
        let j = serde_json::to_string(&c).unwrap();
        let p: TokenClaims = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn encoded_token_is_compact() {
        let i = issuer();
        let t = i.mint(claims()).unwrap();
        // aeth.v1.<payload>.<sig> — sig is ~43 b64 chars.
        assert!(t.len() > 100);
        assert!(!t.is_empty());
    }

    #[test]
    fn issuer_id_returned() {
        let i = issuer();
        assert_eq!(i.issuer_id(), "aeth-issuer-1");
    }

    #[test]
    fn nonce_is_unique_per_token() {
        let i = issuer();
        let t1 = i.mint(claims()).unwrap();
        let t2 = i.mint(claims()).unwrap();
        assert_ne!(t1.encoded(), t2.encoded());
    }

    #[test]
    fn permissions_enforced_via_has_permission() {
        let c = TokenClaims::builder("i", "s", "T", "P")
            .permissions(vec![Permission::SealRead, Permission::AuditRead])
            .build();
        assert!(c.has_permission(Permission::SealRead));
        assert!(!c.has_permission(Permission::SealAppend));
    }

    #[test]
    fn ttl_setter_works() {
        let c = TokenClaims::builder("i", "s", "T", "P")
            .ttl(time::Duration::seconds(60))
            .build();
        let dur = c.expires_at().unwrap() - c.issued_at().unwrap();
        assert!(dur.whole_seconds() >= 59 && dur.whole_seconds() <= 60);
    }

    #[test]
    fn token_with_zero_ttl_is_immediately_expired() {
        let c = TokenClaims::builder("i", "s", "T", "P")
            .ttl(time::Duration::ZERO)
            .build();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(c.is_expired());
    }

    #[test]
    fn long_secret_ok_for_hmac() {
        let i = TokenIssuer::new("i1", &[0xab; 256]);
        let v = TokenVerifier::new("i1", &[0xab; 256]);
        let c = TokenClaims::builder("i1", "s", "T", "P").build();
        let t = i.mint(c).unwrap();
        v.verify(t.encoded()).unwrap();
    }

    #[test]
    fn short_secret_ok_for_hmac() {
        let i = TokenIssuer::new("i1", b"k");
        let v = TokenVerifier::new("i1", b"k");
        let c = TokenClaims::builder("i1", "s", "T", "P").build();
        let t = i.mint(c).unwrap();
        v.verify(t.encoded()).unwrap();
    }
}

//! The sealed transport (docs/SERVER.md, section 2) and the code-derived keys of pairing
//! (section 3). Everything here has a twin in the app's `app/src/services/live/server-wire.ts` and must
//! produce the same bytes as WebCrypto: P-256 points in uncompressed SEC1 form, ECDH secrets
//! as the x-coordinate, ECDSA signatures as raw r‖s, AES-256-GCM with 12-byte IVs.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const RPC_INFO: &[u8] = b"mildly-rpc-v1";
pub const REQ_AAD: &[u8] = b"mildly-req";
pub const RES_AAD: &[u8] = b"mildly-res";
pub const PAIR_SALT: &[u8] = b"mildly-pair-v1";
pub const PAIR_ROUNDS: u32 = 300_000;

pub fn b64(bytes: &[u8]) -> String {
  B64.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>> {
  B64.decode(text.trim_end_matches('=')).map_err(|e| anyhow!("bad base64: {e}"))
}

pub fn random(n: usize) -> Vec<u8> {
  let mut out = vec![0u8; n];
  OsRng.fill_bytes(&mut out);
  out
}

/// The server's long-lived key.
pub struct ServerKey {
  secret: SecretKey,
  public_raw: Vec<u8>,
}

impl ServerKey {
  pub fn generate() -> Self {
    Self::from_secret(SecretKey::random(&mut OsRng))
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    Ok(Self::from_secret(SecretKey::from_slice(bytes).map_err(|_| anyhow!("bad server key"))?))
  }

  fn from_secret(secret: SecretKey) -> Self {
    let public_raw = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
    Self { secret, public_raw }
  }

  pub fn secret_bytes(&self) -> Vec<u8> {
    self.secret.to_bytes().to_vec()
  }

  /// Uncompressed SEC1, as WebCrypto exports a raw P-256 key.
  pub fn public_raw(&self) -> &[u8] {
    &self.public_raw
  }

  /// What the QR code carries: the first 128 bits of SHA-256 of the public key.
  pub fn fingerprint(&self) -> String {
    fingerprint(&self.public_raw)
  }

  /// The AES key for one request, from the client's ephemeral key.
  pub fn request_key(&self, ephemeral_raw: &[u8]) -> Result<Aes256Gcm> {
    let ephemeral = PublicKey::from_sec1_bytes(ephemeral_raw).map_err(|_| anyhow!("bad ephemeral key"))?;
    let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), ephemeral.as_affine());
    let mut salt = ephemeral_raw.to_vec();
    salt.extend_from_slice(&self.public_raw);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes());
    let mut key = [0u8; 32];
    hk.expand(RPC_INFO, &mut key).map_err(|_| anyhow!("hkdf"))?;
    Ok(Aes256Gcm::new_from_slice(&key).expect("32-byte key"))
  }
}

pub fn fingerprint(public_raw: &[u8]) -> String {
  b64(&Sha256::digest(public_raw)[..16])
}

pub fn open(key: &Aes256Gcm, iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
  if iv.len() != 12 {
    return Err(anyhow!("bad iv"));
  }
  let iv: [u8; 12] = iv.try_into().map_err(|_| anyhow!("bad iv"))?;
  key.decrypt(&Nonce::from(iv), Payload { msg: ciphertext, aad }).map_err(|_| anyhow!("cannot open"))
}

/// Returns (iv, ciphertext).
pub fn seal(key: &Aes256Gcm, plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
  let iv: [u8; 12] = random(12).try_into().expect("12 bytes");
  let ct = key.encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad }).expect("aes-gcm encrypt");
  (iv.to_vec(), ct)
}

/// Checks a device's raw r‖s ECDSA P-256 / SHA-256 signature, as WebCrypto makes them.
pub fn verify(device_key_raw: &[u8], message: &[u8], signature_raw: &[u8]) -> bool {
  let Ok(key) = VerifyingKey::from_sec1_bytes(device_key_raw) else { return false };
  let Ok(sig) = Signature::from_slice(signature_raw) else { return false };
  // WebCrypto does not normalise s; both forms are valid ECDSA.
  let sig = sig.normalize_s().unwrap_or(sig);
  key.verify(message, &sig).is_ok()
}

pub fn sha256_b64(bytes: &[u8]) -> String {
  b64(&Sha256::digest(bytes))
}

/* ---------- pairing ---------- */

/// Slow on purpose: someone who sees an announcement must not be able to try every code.
pub fn code_key(code: &str) -> [u8; 32] {
  let mut out = [0u8; 32];
  pbkdf2::pbkdf2_hmac::<Sha256>(code.as_bytes(), PAIR_SALT, PAIR_ROUNDS, &mut out);
  out
}

/// The rendezvous topic and LAN query for a code: meaningless without it.
pub fn topic(code_key: &[u8; 32]) -> String {
  let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(code_key).expect("hmac key");
  mac.update(b"topic");
  format!("mildly-{}", hex::encode(&mac.finalize().into_bytes()[..12]))
}

/// `HMAC(codeKey, label)`: the proof a joining device sends is `code_tag(key, b"proof")`.
pub fn code_tag(code_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
  let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(code_key).expect("hmac key");
  mac.update(label);
  mac.finalize().into_bytes().into()
}

/// The key the announcement is sealed with. An invite's device sends it instead of the code.
pub fn announce_key(code_key: &[u8; 32]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(None, code_key);
  let mut key = [0u8; 32];
  hk.expand(b"mildly-announce-v1", &mut key).expect("hkdf");
  key
}

/// `base64url(iv ‖ ciphertext)` of the announcement JSON.
pub fn seal_announcement(announce_key: &[u8; 32], json: &[u8]) -> String {
  let key = Aes256Gcm::new_from_slice(announce_key).expect("32-byte key");
  let (iv, ct) = seal(&key, json, b"mildly-announce");
  let mut out = iv;
  out.extend_from_slice(&ct);
  b64(&out)
}

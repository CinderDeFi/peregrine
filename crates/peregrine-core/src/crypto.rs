//! Hashing and signing primitives.
//!
//! BLAKE3 everywhere: it is fast enough to hash at NIC line-rate on the
//! tile architecture we're heading toward, and its tree mode will later let
//! us hash erasure-coded shreds incrementally.

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

/// A 32-byte BLAKE3 hash. The universal content identifier for blocks,
/// stream records, table rows, and state roots.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// Hash arbitrary bytes.
    pub fn digest(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }

    /// Hash any serializable value via its bincode encoding.
    ///
    /// NOTE(prod): canonical encoding will be replaced with a fixed wire
    /// format (SSZ-style) before any cross-implementation testing; bincode
    /// is a bootstrap convenience only.
    pub fn digest_of<T: Serialize>(value: &T) -> Self {
        let bytes = bincode::serialize(value).expect("infallible in-memory serialize");
        Self::digest(&bytes)
    }

    /// Domain-separated combination of two child hashes (Merkle interior node).
    pub fn combine(left: &Hash, right: &Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"peregrine.merkle.node.v1");
        hasher.update(&left.0);
        hasher.update(&right.0);
        Hash(*hasher.finalize().as_bytes())
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.short())
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Ed25519 public key (validator / publisher identity).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pk:{}", hex::encode(&self.0[..4]))
    }
}

/// Detached Ed25519 signature.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_bytes64")] pub [u8; 64]);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sig:{}", hex::encode(&self.0[..4]))
    }
}

/// serde helper: [u8; 64] doesn't implement Serialize/Deserialize directly
/// on older serde; encode as a byte sequence.
mod serde_bytes64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Signing keypair. Wraps ed25519-dalek so callers never touch the raw lib.
pub struct Keypair {
    signing: ed25519_dalek::SigningKey,
}

impl Keypair {
    /// Generate a fresh keypair (dev/test). Production keys come from the
    /// DVT key-ceremony pipeline, never from local RNG.
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::generate(rng),
        }
    }

    /// Reconstruct a keypair from its 32-byte secret seed. A node reloads its
    /// signing key from disk on restart via this; the bytes are the only thing
    /// that must persist for the same validator identity to come back.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret seed. Handle as sensitive key material.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    /// Sign a message with domain separation.
    pub fn sign(&self, domain: &'static [u8], msg: &[u8]) -> Signature {
        let mut buf = Vec::with_capacity(domain.len() + msg.len());
        buf.extend_from_slice(domain);
        buf.extend_from_slice(msg);
        Signature(self.signing.sign(&buf).to_bytes())
    }
}

/// Verify a domain-separated signature.
pub fn verify(
    pk: &PublicKey,
    domain: &'static [u8],
    msg: &[u8],
    sig: &Signature,
) -> Result<(), crate::CoreError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk.0)
        .map_err(|_| crate::CoreError::BadSignature)?;
    let mut buf = Vec::with_capacity(domain.len() + msg.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(msg);
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify(&buf, &sig)
        .map_err(|_| crate::CoreError::BadSignature)
}

//! DAG vertices (a.k.a. blocks). One validator proposes one vertex per round.
//!
//! A vertex carries:
//! * its author + round,
//! * hashes of a **quorum of parents** from the previous round
//!   (this is what makes the DAG a consensus structure: including a parent
//!   is an implicit vote for that parent's entire causal history),
//! * an opaque payload (transactions and stream shreds — consensus does not
//!   interpret payload bytes; the execution/data planes do),
//! * the author's signature over the header.

use peregrine_core::{crypto, Hash, Keypair, PublicKey, Round, Signature, ValidatorId};
use serde::{Deserialize, Serialize};

/// Signing domain for vertex headers.
pub const VERTEX_DOMAIN: &[u8] = b"peregrine.stoop.vertex.v1";

/// A single opaque payload item. The node layer encodes transactions and
/// stream shreds into these; consensus only orders them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadItem(pub Vec<u8>);

/// The ordered payload carried by one vertex.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Payload {
    pub items: Vec<PayloadItem>,
}

impl Payload {
    pub fn digest(&self) -> Hash {
        Hash::digest_of(&self.items)
    }
}

/// Everything that is signed. Kept separate from [`Vertex`] so the signature
/// preimage is unambiguous and payload bytes can later be disseminated as
/// erasure-coded shreds while headers travel on the fast path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VertexHeader {
    pub author: ValidatorId,
    pub round: Round,
    /// Parent vertex hashes from `round - 1`. Must represent a stake quorum.
    pub parents: Vec<Hash>,
    /// Commitment to the payload bytes.
    pub payload_digest: Hash,
    /// Advisory wall-clock timestamp (ns). NOT a consensus input.
    pub timestamp_ns: u64,
}

/// A full, signed DAG vertex.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vertex {
    pub header: VertexHeader,
    pub payload: Payload,
    pub signature: Signature,
    /// Cached content hash of the header (identity of this vertex).
    #[serde(skip)]
    cached_hash: Option<Hash>,
}

impl Vertex {
    /// Build and sign a new vertex.
    pub fn new_signed(
        keypair: &Keypair,
        author: ValidatorId,
        round: Round,
        parents: Vec<Hash>,
        payload: Payload,
    ) -> Self {
        let header = VertexHeader {
            author,
            round,
            parents,
            payload_digest: payload.digest(),
            timestamp_ns: now_ns(),
        };
        let msg = bincode::serialize(&header).expect("header serialize");
        let signature = keypair.sign(VERTEX_DOMAIN, &msg);
        let mut v = Self {
            header,
            payload,
            signature,
            cached_hash: None,
        };
        v.cached_hash = Some(v.compute_hash());
        v
    }

    /// The vertex identity: hash of the signed header.
    pub fn hash(&self) -> Hash {
        self.cached_hash.unwrap_or_else(|| self.compute_hash())
    }

    fn compute_hash(&self) -> Hash {
        Hash::digest_of(&self.header)
    }

    /// Verify signature and payload commitment against the author's key.
    pub fn verify(&self, author_pk: &PublicKey) -> Result<(), VertexError> {
        if self.payload.digest() != self.header.payload_digest {
            return Err(VertexError::PayloadMismatch);
        }
        let msg = bincode::serialize(&self.header).map_err(|_| VertexError::Codec)?;
        crypto::verify(author_pk, VERTEX_DOMAIN, &msg, &self.signature)
            .map_err(|_| VertexError::BadSignature)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VertexError {
    #[error("payload digest does not match header commitment")]
    PayloadMismatch,
    #[error("bad vertex signature")]
    BadSignature,
    #[error("serialization failure")]
    Codec,
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

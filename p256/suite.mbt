// RFC 9591 §6.4 FROST(P-256, SHA-256) ciphersuite constants and domain-separated hash functions.
// Uses RFC 9380 expand_message_xmd(SHA-256) with L = 48 for hash_to_field (H1, H2, H3, H_dkg),
// and domain-separated SHA-256 for H4 and H5.

///|
pub const CONTEXT_STRING : String = "FROST-P256-SHA256-v1"

///|
pub const NE : Int32 = 33

///|
pub const NS : Int32 = 32

///|
fn hash_to_scalar(msg : Bytes, dst : String) -> Scalar {
  let dst_bytes = @crypto.ascii_bytes(dst)
  let uniform = match @crypto.expand_message_xmd_sha256(msg, dst_bytes, 48) {
    Ok(b) => b
    Err(e) => abort(e)
  }
  match Scalar::from_wide_be_bytes(uniform) {
    Ok(s) => s
    Err(e) => abort(e)
  }
}

// RFC 9591 §6.4 H1: binding factor hash (DST = "FROST-P256-SHA256-v1rho", L = 48).

///|
pub fn h1(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "rho")
}

// RFC 9591 §6.4 H2: challenge hash (DST = "FROST-P256-SHA256-v1chal", L = 48).

///|
pub fn h2(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "chal")
}

// RFC 9591 §6.4 H3: nonce generation hash (DST = "FROST-P256-SHA256-v1nonce", L = 48).

///|
pub fn h3(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "nonce")
}

// RFC 9591 §6.4 H4: message pre-hash = SHA-256("FROST-P256-SHA256-v1msg" || msg).

///|
pub fn h4(msg : Bytes) -> Bytes {
  @crypto.sha256_concat([@crypto.ascii_bytes(CONTEXT_STRING + "msg"), msg])
}

// RFC 9591 §6.4 H5: commitment list hash = SHA-256("FROST-P256-SHA256-v1com" || msg).

///|
pub fn h5(msg : Bytes) -> Bytes {
  @crypto.sha256_concat([@crypto.ascii_bytes(CONTEXT_STRING + "com"), msg])
}

// Domain-separated hash for Pedersen DKG Schnorr PoK (DST = "FROST-P256-SHA256-v1dkg", L = 48).

///|
pub fn h_dkg(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "dkg")
}

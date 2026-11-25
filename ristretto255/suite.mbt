///|
/// RFC 9591 §6.2 FROST(ristretto255, SHA-512) ciphersuite constants and
/// domain-separated hash functions (H1–H5 and H_dkg).

///|
pub const CONTEXT_STRING : String = "FROST-RISTRETTO255-SHA512-v1"

///|
pub const NE : Int32 = 32

///|
pub const NS : Int32 = 32

///|
fn hash_to_scalar(msg : Bytes, dst : String) -> Scalar {
  let digest = @crypto.sha512_concat([@crypto.ascii_bytes(dst), msg])
  match Scalar::from_bytes_mod_order_wide(digest) {
    Ok(s) => s
    Err(e) => abort(e)
  }
}

///|
/// RFC 9591 §6.2 H1: binding factor hash.
/// Computes SHA-512("FROST-RISTRETTO255-SHA512-v1rho" || msg) mod l.
pub fn h1(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "rho")
}

///|
/// RFC 9591 §6.2 H2: challenge hash.
/// Computes SHA-512("FROST-RISTRETTO255-SHA512-v1chal" || msg) mod l.
pub fn h2(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "chal")
}

///|
/// RFC 9591 §6.2 H3: nonce generation hash.
/// Computes SHA-512("FROST-RISTRETTO255-SHA512-v1nonce" || msg) mod l.
pub fn h3(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "nonce")
}

///|
/// RFC 9591 §6.2 H4: message pre-hash = SHA-512("FROST-RISTRETTO255-SHA512-v1msg" || msg) (64 bytes).
pub fn h4(msg : Bytes) -> Bytes {
  @crypto.sha512_concat([@crypto.ascii_bytes(CONTEXT_STRING + "msg"), msg])
}

///|
/// RFC 9591 §6.2 H5: commitment list hash = SHA-512("FROST-RISTRETTO255-SHA512-v1com" || msg) (64 bytes).
pub fn h5(msg : Bytes) -> Bytes {
  @crypto.sha512_concat([@crypto.ascii_bytes(CONTEXT_STRING + "com"), msg])
}

///|
/// Domain-separated hash for Pedersen DKG Schnorr PoK.
/// Computes SHA-512("FROST-RISTRETTO255-SHA512-v1dkg" || msg) mod l.
pub fn h_dkg(msg : Bytes) -> Scalar {
  hash_to_scalar(msg, CONTEXT_STRING + "dkg")
}

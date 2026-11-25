///|
/// RFC 9591 §4.1 and §5.1 hedged nonce generation and one-time-use signing
/// nonce state machine with mandatory consumption and zeroization.

///|
/// RFC 9591 §4.1 hedged nonce generation with caller-provided 32-byte randomness:
/// returns `H3(random_bytes || SerializeScalar(secret))`.
pub fn[S, E] nonce_generate_with_randomness(
  ops : SuiteOps[S, E],
  secret : S,
  random_bytes : Bytes,
) -> Result[S, FrostError] {
  if random_bytes.length() != 32 {
    return Err(
      FrostError::InvalidParameters("nonce randomness must be 32 bytes"),
    )
  }
  let secret_enc = (ops.serialize_scalar)(secret)
  Ok((ops.h3)(@crypto.concat_bytes([random_bytes, secret_enc])))
}

///|
/// RFC 9591 §4.1 hedged nonce generation drawing 32 fresh bytes from `drbg`.
pub fn[S, E] nonce_generate(
  ops : SuiteOps[S, E],
  secret : S,
  drbg : @crypto.Drbg,
) -> S {
  let random_bytes = drbg.next_bytes(32)
  let secret_enc = (ops.serialize_scalar)(secret)
  (ops.h3)(@crypto.concat_bytes([random_bytes, secret_enc]))
}

///|
/// Public Round 1 signing commitments (hiding_nonce_commitment, binding_nonce_commitment).
#derive(Debug)
pub(all) struct SigningCommitments[E] {
  hiding : E
  binding : E
}

///|
/// Secret Round 1 signing nonces with strict one-time-use enforcement.
/// All fields are private; calling `sign` immediately marks the nonces as used
/// and overwrites `hiding` and `binding` with `scalar_zero`.
pub struct SigningNonces[S, E] {
  priv mut hiding : S
  priv mut binding : S
  priv commitments : SigningCommitments[E]
  priv mut used : Bool
}

///|
/// Returns `true` if this nonce pair has already been consumed by `sign`.
pub fn[S, E] SigningNonces::is_used(self : SigningNonces[S, E]) -> Bool {
  self.used
}

///|
/// Returns the public `SigningCommitments` corresponding to these nonces.
pub fn[S, E] SigningNonces::commitments(
  self : SigningNonces[S, E],
) -> SigningCommitments[E] {
  self.commitments
}

///|
/// Consumes and zeroizes the secret nonces. Any subsequent attempt returns
/// `Err(FrostError::NonceAlreadyUsed)`.
fn[S, E] SigningNonces::consume(
  self : SigningNonces[S, E],
  ops : SuiteOps[S, E],
) -> Result[(S, S), FrostError] {
  if self.used {
    return Err(FrostError::NonceAlreadyUsed)
  }
  let h = self.hiding
  let b = self.binding
  self.hiding = (ops.scalar_zero)()
  self.binding = (ops.scalar_zero)()
  self.used = true
  Ok((h, b))
}

///|
/// RFC 9591 §5.1 Round 1 commitment generation with explicit 32-byte hiding
/// and binding randomness (for deterministic RFC 9591 Appendix E verification).
pub fn[S, E] commit_with_randomness(
  ops : SuiteOps[S, E],
  secret_share : S,
  hiding_randomness : Bytes,
  binding_randomness : Bytes,
) -> Result[(SigningNonces[S, E], SigningCommitments[E]), FrostError] {
  let hiding = match
    nonce_generate_with_randomness(ops, secret_share, hiding_randomness) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let binding = match
    nonce_generate_with_randomness(ops, secret_share, binding_randomness) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if (ops.scalar_is_zero)(hiding) || (ops.scalar_is_zero)(binding) {
    return Err(FrostError::IdentityElement)
  }
  let hiding_comm = (ops.scalar_base_mul)(hiding)
  let binding_comm = (ops.scalar_base_mul)(binding)
  let commitments : SigningCommitments[E] = {
    hiding: hiding_comm,
    binding: binding_comm,
  }
  let nonces : SigningNonces[S, E] = {
    hiding,
    binding,
    commitments,
    used: false,
  }
  Ok((nonces, commitments))
}

///|
/// RFC 9591 §5.1 Round 1 commitment generation using `drbg`.
pub fn[S, E] commit(
  ops : SuiteOps[S, E],
  secret_share : S,
  drbg : @crypto.Drbg,
) -> Result[(SigningNonces[S, E], SigningCommitments[E]), FrostError] {
  while true {
    let h_rand = drbg.next_bytes(32)
    let b_rand = drbg.next_bytes(32)
    match commit_with_randomness(ops, secret_share, h_rand, b_rand) {
      Ok(res) => return Ok(res)
      Err(FrostError::IdentityElement) => continue
      Err(e) => return Err(e)
    }
  }
  Err(FrostError::IdentityElement)
}

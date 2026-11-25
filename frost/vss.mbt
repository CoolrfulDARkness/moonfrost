///|
/// RFC 9591 Appendix C: Trusted Dealer Shamir Secret Sharing and Feldman
/// Verifiable Secret Sharing (VSS).

///|
/// Per-participant secret key package produced by Trusted Dealer or DKG.
#derive(Debug)
pub(all) struct KeyPackage[S, E] {
  identifier : Int32
  signing_share : S
  verifying_share : E
  verifying_key : E
  min_signers : Int32
  max_signers : Int32
}

///|
/// Public group key material shared by Coordinator and all participants.
#derive(Debug)
pub(all) struct PublicKeyPackage[E] {
  verifying_shares : Array[(Int32, E)]
  verifying_key : E
  min_signers : Int32
  max_signers : Int32
}

///|
/// Looks up the verifying share (public key share PK_i) for participant `id`.
pub fn[E] PublicKeyPackage::verifying_share_for(
  self : PublicKeyPackage[E],
  id : Int32,
) -> Result[E, FrostError] {
  if id <= 0 {
    return Err(FrostError::InvalidParticipantId(id))
  }
  for i = 0; i < self.verifying_shares.length(); i = i + 1 {
    let (pid, pk) = self.verifying_shares[i]
    if pid == id {
      return Ok(pk)
    }
  }
  Err(FrostError::InvalidParticipantId(id))
}

///|
/// Feldman VSS vector commitment [C_0, C_1, ..., C_{t-1}] where C_k = a_k * G.
#derive(Debug)
pub(all) struct VssCommitment[E] {
  coeffs : Array[E]
}

///|
const MAX_ALLOWED_PARTICIPANTS : Int32 = 65535

///|
fn validate_threshold(
  min_signers : Int32,
  max_signers : Int32,
) -> Result[Unit, FrostError] {
  if min_signers < 2 {
    return Err(FrostError::InvalidThreshold("min_signers must be at least 2"))
  }
  if max_signers < min_signers {
    return Err(
      FrostError::InvalidThreshold("max_signers must be >= min_signers"),
    )
  }
  if max_signers > MAX_ALLOWED_PARTICIPANTS {
    return Err(
      FrostError::InvalidThreshold(
        "max_signers exceeds maximum supported participants (65535)",
      ),
    )
  }
  Ok(())
}

///|
/// Evaluates sum_{j=0}^{t-1} (id^j) * C_j using Horner's method on group elements.
/// Rejects empty commitments or any coefficient equal to the group identity element.
fn[S, E] eval_vss_commitment(
  ops : SuiteOps[S, E],
  commitment : VssCommitment[E],
  id : Int32,
) -> Result[E, FrostError] {
  let x = match id_to_scalar(ops, id) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let len = commitment.coeffs.length()
  if len == 0 {
    return Err(FrostError::InvalidVssCommitment("empty VSS commitment"))
  }
  for k = 0; k < len; k = k + 1 {
    if (ops.element_is_identity)(commitment.coeffs[k]) {
      return Err(FrostError::IdentityElement)
    }
  }
  let mut acc = commitment.coeffs[len - 1]
  for j = len - 2; j >= 0; j = j - 1 {
    acc = (ops.scalar_mul_elem)(acc, x)
    acc = (ops.element_add)(acc, commitment.coeffs[j])
  }
  Ok(acc)
}

///|
/// Splits `secret` into `max_signers` Shamir secret shares using polynomial
/// `[secret, coeffs_tail[0], ..., coeffs_tail[t-2]]` (RFC 9591 Appendix C.1).
pub fn[S, E] secret_share_shard(
  ops : SuiteOps[S, E],
  secret : S,
  coeffs_tail : Array[S],
  max_signers : Int32,
) -> Result[(Array[(Int32, S)], Array[S]), FrostError] {
  let min_signers = coeffs_tail.length() + 1
  match validate_threshold(min_signers, max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if (ops.scalar_is_zero)(coeffs_tail[coeffs_tail.length() - 1]) {
    return Err(
      FrostError::InvalidThreshold(
        "highest-degree polynomial coefficient must be non-zero",
      ),
    )
  }
  let coeffs : Array[S] = [secret]
  for i = 0; i < coeffs_tail.length(); i = i + 1 {
    coeffs.push(coeffs_tail[i])
  }
  let shares : Array[(Int32, S)] = []
  for id = 1; id <= max_signers; id = id + 1 {
    let x = (ops.scalar_from_u32)(id.reinterpret_as_uint())
    let y = polynomial_evaluate(ops, x, coeffs)
    shares.push((id, y))
  }
  Ok((shares, coeffs))
}

///|
/// Combines at least `min_signers` Shamir secret shares to reconstruct `f(0)`
/// (RFC 9591 Appendix C.1).
pub fn[S, E] secret_share_combine(
  ops : SuiteOps[S, E],
  shares : Array[(Int32, S)],
  min_signers : Int32,
) -> Result[S, FrostError] {
  if min_signers < 1 {
    return Err(FrostError::InvalidThreshold("min_signers must be at least 1"))
  }
  if shares.length() < min_signers {
    return Err(
      FrostError::InsufficientParticipants(shares.length(), min_signers),
    )
  }
  polynomial_interpolate_constant(ops, shares)
}

///|
/// Computes Feldman VSS commitment `[a_0*G, a_1*G, ..., a_{t-1}*G]`
/// (RFC 9591 Appendix C.2).
pub fn[S, E] vss_commit(
  ops : SuiteOps[S, E],
  coeffs : Array[S],
) -> VssCommitment[E] {
  let out : Array[E] = []
  for i = 0; i < coeffs.length(); i = i + 1 {
    out.push((ops.scalar_base_mul)(coeffs[i]))
  }
  { coeffs: out, }
}

///|
/// Verifies that `share * G == sum_{j=0}^{t-1} (id^j) * commitment.coeffs[j]`
/// (RFC 9591 Appendix C.2). Rejects commitments containing identity elements
/// or evaluating to the group identity.
pub fn[S, E] vss_verify(
  ops : SuiteOps[S, E],
  id : Int32,
  share : S,
  commitment : VssCommitment[E],
) -> Result[Bool, FrostError] {
  let rhs = match eval_vss_commitment(ops, commitment, id) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if (ops.element_is_identity)(rhs) {
    return Err(FrostError::IdentityElement)
  }
  let lhs = (ops.scalar_base_mul)(share)
  Ok((ops.element_eq)(lhs, rhs))
}

///|
/// Derives the group public key and per-participant verifying shares from a
/// Feldman VSS commitment (RFC 9591 Appendix C.2).
pub fn[S, E] derive_group_info(
  ops : SuiteOps[S, E],
  max_signers : Int32,
  min_signers : Int32,
  commitment : VssCommitment[E],
) -> Result[PublicKeyPackage[E], FrostError] {
  match validate_threshold(min_signers, max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if commitment.coeffs.length() != min_signers {
    return Err(
      FrostError::InvalidVssCommitment(
        "commitment length does not match min_signers",
      ),
    )
  }
  for k = 0; k < commitment.coeffs.length(); k = k + 1 {
    if (ops.element_is_identity)(commitment.coeffs[k]) {
      return Err(FrostError::IdentityElement)
    }
  }
  let verifying_key = commitment.coeffs[0]
  let verifying_shares : Array[(Int32, E)] = []
  for id = 1; id <= max_signers; id = id + 1 {
    let pk_i = match eval_vss_commitment(ops, commitment, id) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    if (ops.element_is_identity)(pk_i) {
      return Err(FrostError::IdentityElement)
    }
    verifying_shares.push((id, pk_i))
  }
  Ok({ verifying_shares, verifying_key, min_signers, max_signers, })
}

///|
/// Deterministic Trusted Dealer key generation using a caller-supplied group
/// secret and polynomial tail coefficients (RFC 9591 Appendix C & Appendix E).
pub fn[S, E] trusted_dealer_keygen_with_secret(
  ops : SuiteOps[S, E],
  secret : S,
  coeffs_tail : Array[S],
  max_signers : Int32,
) -> Result[
  (Array[KeyPackage[S, E]], PublicKeyPackage[E], VssCommitment[E]),
  FrostError,
] {
  let min_signers = coeffs_tail.length() + 1
  match validate_threshold(min_signers, max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if (ops.scalar_is_zero)(secret) {
    return Err(FrostError::IdentityElement)
  }
  let (shares, full_coeffs) = match
    secret_share_shard(ops, secret, coeffs_tail, max_signers) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let commitment = vss_commit(ops, full_coeffs)
  let pub_pkg = match
    derive_group_info(ops, max_signers, min_signers, commitment) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let key_packages : Array[KeyPackage[S, E]] = []
  for i = 0; i < shares.length(); i = i + 1 {
    let (id, share) = shares[i]
    let valid = match vss_verify(ops, id, share, commitment) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    if !valid {
      return Err(
        FrostError::InvalidVssCommitment(
          "internal VSS share verification failed",
        ),
      )
    }
    let pk_i = match pub_pkg.verifying_share_for(id) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    key_packages.push({
      identifier: id,
      signing_share: share,
      verifying_share: pk_i,
      verifying_key: pub_pkg.verifying_key,
      min_signers,
      max_signers,
    })
  }
  Ok((key_packages, pub_pkg, commitment))
}

///|
/// Randomized Trusted Dealer key generation (RFC 9591 Appendix C).
pub fn[S, E] trusted_dealer_keygen(
  ops : SuiteOps[S, E],
  drbg : @crypto.Drbg,
  max_signers : Int32,
  min_signers : Int32,
) -> Result[
  (Array[KeyPackage[S, E]], PublicKeyPackage[E], VssCommitment[E]),
  FrostError,
] {
  match validate_threshold(min_signers, max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let secret = random_nonzero_scalar(ops, drbg)
  let coeffs_tail : Array[S] = []
  for _i = 0; _i < min_signers - 1; _i = _i + 1 {
    coeffs_tail.push(random_nonzero_scalar(ops, drbg))
  }
  trusted_dealer_keygen_with_secret(ops, secret, coeffs_tail, max_signers)
}

///|
/// RFC 9591 §4.2 and Appendix C.1.1 polynomial evaluation and Lagrange
/// interpolation over the ciphersuite scalar field.

///|
/// Evaluates polynomial f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[d]*x^d
/// using Horner's method (RFC 9591 Appendix C.1.1).
pub fn[S, E] polynomial_evaluate(
  ops : SuiteOps[S, E],
  x : S,
  coeffs : Array[S],
) -> S {
  let mut value = (ops.scalar_zero)()
  for i = coeffs.length() - 1; i >= 0; i = i - 1 {
    value = (ops.scalar_mul)(value, x)
    value = (ops.scalar_add)(value, coeffs[i])
  }
  value
}

///|
/// Derives the Lagrange interpolating coefficient lambda_i evaluated at x = 0
/// for `signer_id` within `participant_ids` (RFC 9591 §4.2).
/// Strictly validates that all IDs are > 0, unique, and `signer_id` is present.
pub fn[S, E] derive_interpolating_value(
  ops : SuiteOps[S, E],
  participant_ids : Array[Int32],
  signer_id : Int32,
) -> Result[S, FrostError] {
  if signer_id <= 0 {
    return Err(FrostError::InvalidParticipantId(signer_id))
  }
  let n = participant_ids.length()
  if n == 0 {
    return Err(FrostError::InvalidParticipantId(signer_id))
  }
  let mut found = false
  for i = 0; i < n; i = i + 1 {
    let id = participant_ids[i]
    if id <= 0 {
      return Err(FrostError::InvalidParticipantId(id))
    }
    if id == signer_id {
      found = true
    }
    for j = i + 1; j < n; j = j + 1 {
      if participant_ids[j] == id {
        return Err(FrostError::DuplicateParticipant(id))
      }
    }
  }
  if !found {
    return Err(FrostError::InvalidParticipantId(signer_id))
  }
  let x_i = (ops.scalar_from_u32)(signer_id.reinterpret_as_uint())
  let mut numerator = (ops.scalar_one)()
  let mut denominator = (ops.scalar_one)()
  for i = 0; i < n; i = i + 1 {
    let id_j = participant_ids[i]
    if id_j == signer_id {
      continue
    }
    let x_j = (ops.scalar_from_u32)(id_j.reinterpret_as_uint())
    numerator = (ops.scalar_mul)(numerator, x_j)
    denominator = (ops.scalar_mul)(denominator, (ops.scalar_sub)(x_j, x_i))
  }
  let denom_inv = match (ops.scalar_invert)(denominator) {
    Ok(inv) => inv
    Err(e) => return Err(FrostError::InvalidScalar(e))
  }
  Ok((ops.scalar_mul)(numerator, denom_inv))
}

///|
/// Recovers the constant term f(0) of the interpolating polynomial defined by
/// `shares` = [(x_i, f(x_i)), ...] (RFC 9591 Appendix C.1.1).
pub fn[S, E] polynomial_interpolate_constant(
  ops : SuiteOps[S, E],
  shares : Array[(Int32, S)],
) -> Result[S, FrostError] {
  let n = shares.length()
  if n == 0 {
    return Err(FrostError::InvalidParameters("empty share list"))
  }
  let ids : Array[Int32] = []
  for i = 0; i < n; i = i + 1 {
    let (id, _) = shares[i]
    if id <= 0 {
      return Err(FrostError::InvalidParticipantId(id))
    }
    for j = 0; j < i; j = j + 1 {
      if ids[j] == id {
        return Err(FrostError::DuplicateParticipant(id))
      }
    }
    ids.push(id)
  }
  let mut f_zero = (ops.scalar_zero)()
  for i = 0; i < n; i = i + 1 {
    let (id, y) = shares[i]
    let lambda_i = match derive_interpolating_value(ops, ids, id) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let delta = (ops.scalar_mul)(y, lambda_i)
    f_zero = (ops.scalar_add)(f_zero, delta)
  }
  Ok(f_zero)
}

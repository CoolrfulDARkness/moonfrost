///|
/// RFC 9591 §4.3-§4.6, §5.2-§5.4, Appendix A & Appendix B:
/// Binding factor computation, group commitment, Round 2 signature share
/// generation, aggregation with Identifiable Abort, prime-order Schnorr
/// sign/verify, and canonical signature encoding.

///|
/// Entry in the sorted participant commitment list.
#derive(Debug)
pub(all) struct CommitmentEntry[E] {
  identifier : Int32
  commitments : SigningCommitments[E]
}

///|
/// Constructs a `CommitmentEntry` for participant `identifier`.
pub fn[E] CommitmentEntry::new(
  identifier : Int32,
  commitments : SigningCommitments[E],
) -> CommitmentEntry[E] {
  { identifier, commitments, }
}

///|
/// Participant Round 2 signature share.
#derive(Debug)
pub(all) struct SignatureShare[S] {
  identifier : Int32
  share : S
}

///|
/// Schnorr signature `(R, z)` over a prime-order group.
#derive(Debug)
pub(all) struct Signature[S, E] {
  r : E
  z : S
}

///|
/// Strictly validates a commitment list per RFC 9591 §4.3 & §5.2:
/// - `commitment_list.length() >= min_signers`
/// - every participant ID > 0
/// - no duplicate participant IDs
/// - strictly ascending order by identifier
/// - every hiding and binding commitment is non-identity.
pub fn[S, E] validate_commitment_list(
  ops : SuiteOps[S, E],
  commitment_list : Array[CommitmentEntry[E]],
  min_signers : Int32,
) -> Result[Unit, FrostError] {
  if min_signers < 1 {
    return Err(FrostError::InvalidThreshold("min_signers must be at least 1"))
  }
  let n = commitment_list.length()
  if n < min_signers {
    return Err(FrostError::InsufficientParticipants(n, min_signers))
  }
  for i = 0; i < n; i = i + 1 {
    let entry = commitment_list[i]
    if entry.identifier <= 0 {
      return Err(FrostError::InvalidParticipantId(entry.identifier))
    }
    if (ops.element_is_identity)(entry.commitments.hiding) ||
      (ops.element_is_identity)(entry.commitments.binding) {
      return Err(FrostError::IdentityElement)
    }
    for j = i + 1; j < n; j = j + 1 {
      if commitment_list[j].identifier == entry.identifier {
        return Err(FrostError::DuplicateParticipant(entry.identifier))
      }
    }
  }
  for i = 1; i < n; i = i + 1 {
    if commitment_list[i].identifier <= commitment_list[i - 1].identifier {
      return Err(FrostError::UnsortedCommitments)
    }
  }
  Ok(())
}

///|
fn[E] participants_from_commitment_list(
  commitment_list : Array[CommitmentEntry[E]],
) -> Array[Int32] {
  let ids : Array[Int32] = []
  for i = 0; i < commitment_list.length(); i = i + 1 {
    ids.push(commitment_list[i].identifier)
  }
  ids
}

///|
fn[S] binding_factor_for(
  binding_factor_list : Array[(Int32, S)],
  identifier : Int32,
) -> Result[S, FrostError] {
  for i = 0; i < binding_factor_list.length(); i = i + 1 {
    let (id, factor) = binding_factor_list[i]
    if id == identifier {
      return Ok(factor)
    }
  }
  Err(FrostError::InvalidParticipantId(identifier))
}

///|
/// RFC 9591 §4.3: canonically encodes a sorted commitment list as
/// `concat(SerializeScalar(i) || SerializeElement(D_i) || SerializeElement(E_i))`.
pub fn[S, E] encode_group_commitment_list(
  ops : SuiteOps[S, E],
  commitment_list : Array[CommitmentEntry[E]],
) -> Result[Bytes, FrostError] {
  match validate_commitment_list(ops, commitment_list, 1) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let parts : Array[Bytes] = []
  for i = 0; i < commitment_list.length(); i = i + 1 {
    let entry = commitment_list[i]
    let id_scalar = match id_to_scalar(ops, entry.identifier) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let id_enc = (ops.serialize_scalar)(id_scalar)
    let h_enc = match serialize_element_checked(ops, entry.commitments.hiding) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let b_enc = match
      serialize_element_checked(ops, entry.commitments.binding) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    parts.push(id_enc)
    parts.push(h_enc)
    parts.push(b_enc)
  }
  Ok(@crypto.concat_bytes(parts))
}

///|
/// RFC 9591 §4.4: computes per-participant `rho_input` byte strings
/// `SerializeElement(PK) || H4(msg) || H5(encode_group_commitment_list(L)) || SerializeScalar(i)`.
pub fn[S, E] compute_binding_factor_inputs(
  ops : SuiteOps[S, E],
  group_public_key : E,
  commitment_list : Array[CommitmentEntry[E]],
  msg : Bytes,
) -> Result[Array[(Int32, Bytes)], FrostError] {
  let group_pk_enc = match serialize_element_checked(ops, group_public_key) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let encoded_comm = match encode_group_commitment_list(ops, commitment_list) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let msg_hash = (ops.h4)(msg)
  let encoded_comm_hash = (ops.h5)(encoded_comm)
  let rho_input_prefix = @crypto.concat_bytes([
    group_pk_enc, msg_hash, encoded_comm_hash,
  ])
  let out : Array[(Int32, Bytes)] = []
  for i = 0; i < commitment_list.length(); i = i + 1 {
    let id = commitment_list[i].identifier
    let id_scalar = match id_to_scalar(ops, id) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let id_enc = (ops.serialize_scalar)(id_scalar)
    let rho_input = @crypto.concat_bytes([rho_input_prefix, id_enc])
    out.push((id, rho_input))
  }
  Ok(out)
}

///|
/// RFC 9591 §4.4: computes the binding factor list `[(i, H1(rho_input_i)), ...]`.
pub fn[S, E] compute_binding_factors(
  ops : SuiteOps[S, E],
  group_public_key : E,
  commitment_list : Array[CommitmentEntry[E]],
  msg : Bytes,
) -> Result[Array[(Int32, S)], FrostError] {
  let inputs = match
    compute_binding_factor_inputs(ops, group_public_key, commitment_list, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let out : Array[(Int32, S)] = []
  for i = 0; i < inputs.length(); i = i + 1 {
    let (id, rho_input) = inputs[i]
    out.push((id, (ops.h1)(rho_input)))
  }
  Ok(out)
}

///|
/// RFC 9591 §4.5: computes the group commitment `R = sum_i (D_i + rho_i * E_i)`.
pub fn[S, E] compute_group_commitment(
  ops : SuiteOps[S, E],
  commitment_list : Array[CommitmentEntry[E]],
  binding_factor_list : Array[(Int32, S)],
) -> Result[E, FrostError] {
  match validate_commitment_list(ops, commitment_list, 1) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let mut group_commitment = (ops.element_identity)()
  for i = 0; i < commitment_list.length(); i = i + 1 {
    let entry = commitment_list[i]
    let rho = match binding_factor_for(binding_factor_list, entry.identifier) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let binding_nonce = (ops.scalar_mul_elem)(entry.commitments.binding, rho)
    group_commitment = (ops.element_add)(
      group_commitment,
      entry.commitments.hiding,
    )
    group_commitment = (ops.element_add)(group_commitment, binding_nonce)
  }
  if (ops.element_is_identity)(group_commitment) {
    return Err(FrostError::IdentityElement)
  }
  Ok(group_commitment)
}

///|
/// RFC 9591 §4.6: computes the per-message Schnorr challenge
/// `c = H2(SerializeElement(R) || SerializeElement(PK) || msg)`.
pub fn[S, E] compute_challenge(
  ops : SuiteOps[S, E],
  group_commitment : E,
  group_public_key : E,
  msg : Bytes,
) -> Result[S, FrostError] {
  let comm_enc = match serialize_element_checked(ops, group_commitment) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let pk_enc = match serialize_element_checked(ops, group_public_key) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let challenge_input = @crypto.concat_bytes([comm_enc, pk_enc, msg])
  Ok((ops.h2)(challenge_input))
}

///|
/// RFC 9591 §5.2 Round 2 signature share generation.
/// Validates nonces are unused, `commitment_list` is well-formed and includes
/// this signer's exact `(hiding, binding)` commitments, then immediately
/// consumes and zeroizes `nonces` before computing `z_i`.
pub fn[S, E] sign(
  ops : SuiteOps[S, E],
  key_package : KeyPackage[S, E],
  nonces : SigningNonces[S, E],
  msg : Bytes,
  commitment_list : Array[CommitmentEntry[E]],
) -> Result[SignatureShare[S], FrostError] {
  if nonces.is_used() {
    return Err(FrostError::NonceAlreadyUsed)
  }
  match validate_threshold(key_package.min_signers, key_package.max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if key_package.identifier <= 0 ||
    key_package.identifier > key_package.max_signers {
    return Err(FrostError::InvalidParticipantId(key_package.identifier))
  }
  match
    validate_commitment_list(ops, commitment_list, key_package.min_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if commitment_list.length() > key_package.max_signers {
    return Err(
      FrostError::InvalidParameters("commitment_list exceeds max_signers"),
    )
  }
  // Ensure every participant ID in commitment_list is within [1, max_signers]
  // and that this signer's identifier and exact Round 1 commitments appear.
  let own_comms = nonces.commitments()
  let mut matched = false
  for i = 0; i < commitment_list.length(); i = i + 1 {
    let entry = commitment_list[i]
    if entry.identifier > key_package.max_signers {
      return Err(FrostError::InvalidParticipantId(entry.identifier))
    }
    if entry.identifier == key_package.identifier {
      if !(ops.element_eq)(entry.commitments.hiding, own_comms.hiding) ||
        !(ops.element_eq)(entry.commitments.binding, own_comms.binding) {
        return Err(FrostError::CommitmentMismatch(key_package.identifier))
      }
      matched = true
    }
  }
  if !matched {
    return Err(FrostError::InvalidParticipantId(key_package.identifier))
  }
  let binding_factor_list = match
    compute_binding_factors(
      ops,
      key_package.verifying_key,
      commitment_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let binding_factor = match
    binding_factor_for(binding_factor_list, key_package.identifier) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let group_commitment = match
    compute_group_commitment(ops, commitment_list, binding_factor_list) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let participant_list = participants_from_commitment_list(commitment_list)
  let lambda_i = match
    derive_interpolating_value(ops, participant_list, key_package.identifier) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let challenge = match
    compute_challenge(ops, group_commitment, key_package.verifying_key, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  // Consume and zeroize the one-time nonces immediately before computing z_i.
  let (hiding_nonce, binding_nonce) = match nonces.consume(ops) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let term_bind = (ops.scalar_mul)(binding_nonce, binding_factor)
  let term_key = (ops.scalar_mul)(
    (ops.scalar_mul)(lambda_i, key_package.signing_share),
    challenge,
  )
  let sig_share = (ops.scalar_add)(
    (ops.scalar_add)(hiding_nonce, term_bind),
    term_key,
  )
  Ok({ identifier: key_package.identifier, share: sig_share, })
}

///|
/// RFC 9591 §5.3: verifies an individual participant's signature share against
/// their verifying share `PK_i` and Round 1 commitments.
pub fn[S, E] verify_signature_share(
  ops : SuiteOps[S, E],
  identifier : Int32,
  verifying_share : E,
  commitments : SigningCommitments[E],
  sig_share : S,
  commitment_list : Array[CommitmentEntry[E]],
  group_public_key : E,
  msg : Bytes,
) -> Result[Bool, FrostError] {
  if identifier <= 0 {
    return Err(FrostError::InvalidParticipantId(identifier))
  }
  if (ops.element_is_identity)(verifying_share) ||
    (ops.element_is_identity)(commitments.hiding) ||
    (ops.element_is_identity)(commitments.binding) ||
    (ops.element_is_identity)(group_public_key) {
    return Err(FrostError::IdentityElement)
  }
  match validate_commitment_list(ops, commitment_list, 1) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let mut found = false
  for i = 0; i < commitment_list.length(); i = i + 1 {
    let entry = commitment_list[i]
    if entry.identifier == identifier {
      if !(ops.element_eq)(entry.commitments.hiding, commitments.hiding) ||
        !(ops.element_eq)(entry.commitments.binding, commitments.binding) {
        return Err(FrostError::CommitmentMismatch(identifier))
      }
      found = true
      break
    }
  }
  if !found {
    return Err(FrostError::InvalidParticipantId(identifier))
  }
  let binding_factor_list = match
    compute_binding_factors(ops, group_public_key, commitment_list, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let binding_factor = match
    binding_factor_for(binding_factor_list, identifier) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let group_commitment = match
    compute_group_commitment(ops, commitment_list, binding_factor_list) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let comm_share = (ops.element_add)(
    commitments.hiding,
    (ops.scalar_mul_elem)(commitments.binding, binding_factor),
  )
  let challenge = match
    compute_challenge(ops, group_commitment, group_public_key, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let participant_list = participants_from_commitment_list(commitment_list)
  let lambda_i = match
    derive_interpolating_value(ops, participant_list, identifier) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let lhs = (ops.scalar_base_mul)(sig_share)
  let rhs = (ops.element_add)(
    comm_share,
    (ops.scalar_mul_elem)(
      verifying_share,
      (ops.scalar_mul)(challenge, lambda_i),
    ),
  )
  Ok((ops.element_eq)(lhs, rhs))
}

///|
/// RFC 9591 Appendix B: standard single-party Schnorr signing over a prime-order group.
pub fn[S, E] prime_order_sign(
  ops : SuiteOps[S, E],
  msg : Bytes,
  secret_key : S,
  drbg : @crypto.Drbg,
) -> Result[Signature[S, E], FrostError] {
  if (ops.scalar_is_zero)(secret_key) {
    return Err(FrostError::IdentityElement)
  }
  let r = random_nonzero_scalar(ops, drbg)
  let r_elem = (ops.scalar_base_mul)(r)
  let pk = (ops.scalar_base_mul)(secret_key)
  let c = match compute_challenge(ops, r_elem, pk, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let z = (ops.scalar_add)(r, (ops.scalar_mul)(c, secret_key))
  Ok({ r: r_elem, z, })
}

///|
/// RFC 9591 Appendix B: standard Schnorr signature verification over a prime-order group.
pub fn[S, E] prime_order_verify(
  ops : SuiteOps[S, E],
  msg : Bytes,
  sig : Signature[S, E],
  public_key : E,
) -> Result[Bool, FrostError] {
  let c = match compute_challenge(ops, sig.r, public_key, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let lhs = (ops.scalar_base_mul)(sig.z)
  let rhs = (ops.element_add)(sig.r, (ops.scalar_mul_elem)(public_key, c))
  Ok((ops.element_eq)(lhs, rhs))
}

///|
/// RFC 9591 §5.3 & §5.4: aggregates signature shares into a standard Schnorr
/// signature `(R, z)` and verifies it against `pub_keys.verifying_key`.
/// On aggregate verification failure, automatically triggers Identifiable Abort
/// (§5.4) by checking every participant's signature share and returning
/// `Err(FrostError::CheaterDetected(cheaters))` with sorted unique cheater IDs.
pub fn[S, E] aggregate(
  ops : SuiteOps[S, E],
  commitment_list : Array[CommitmentEntry[E]],
  msg : Bytes,
  pub_keys : PublicKeyPackage[E],
  sig_shares : Array[SignatureShare[S]],
) -> Result[Signature[S, E], FrostError] {
  match validate_threshold(pub_keys.min_signers, pub_keys.max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if (ops.element_is_identity)(pub_keys.verifying_key) {
    return Err(FrostError::IdentityElement)
  }
  for i = 0; i < pub_keys.verifying_shares.length(); i = i + 1 {
    let (pid, pk_i) = pub_keys.verifying_shares[i]
    if pid <= 0 || pid > pub_keys.max_signers {
      return Err(FrostError::InvalidParticipantId(pid))
    }
    if (ops.element_is_identity)(pk_i) {
      return Err(FrostError::IdentityElement)
    }
    for j = i + 1; j < pub_keys.verifying_shares.length(); j = j + 1 {
      let (pid2, _) = pub_keys.verifying_shares[j]
      if pid2 == pid {
        return Err(FrostError::DuplicateParticipant(pid))
      }
    }
  }
  match validate_commitment_list(ops, commitment_list, pub_keys.min_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let num = commitment_list.length()
  if num > pub_keys.max_signers {
    return Err(
      FrostError::InvalidParameters("commitment_list exceeds max_signers"),
    )
  }
  for i = 0; i < num; i = i + 1 {
    if commitment_list[i].identifier > pub_keys.max_signers {
      return Err(
        FrostError::InvalidParticipantId(commitment_list[i].identifier),
      )
    }
  }
  if sig_shares.length() < num {
    return Err(FrostError::InsufficientParticipants(sig_shares.length(), num))
  }
  if sig_shares.length() > num {
    return Err(
      FrostError::InvalidParameters(
        "sig_shares length does not match commitment_list",
      ),
    )
  }
  // Check sig_shares IDs are > 0, unique, and match commitment_list 1-to-1.
  for i = 0; i < sig_shares.length(); i = i + 1 {
    let id = sig_shares[i].identifier
    if id <= 0 {
      return Err(FrostError::InvalidParticipantId(id))
    }
    for j = i + 1; j < sig_shares.length(); j = j + 1 {
      if sig_shares[j].identifier == id {
        return Err(FrostError::DuplicateParticipant(id))
      }
    }
    let mut in_comms = false
    for k = 0; k < num; k = k + 1 {
      if commitment_list[k].identifier == id {
        in_comms = true
        break
      }
    }
    if !in_comms {
      return Err(FrostError::InvalidParticipantId(id))
    }
  }
  // Also ensure every commitment_list participant has a verifying share in pub_keys.
  for i = 0; i < num; i = i + 1 {
    match pub_keys.verifying_share_for(commitment_list[i].identifier) {
      Ok(_) => ()
      Err(e) => return Err(e)
    }
  }
  let binding_factor_list = match
    compute_binding_factors(ops, pub_keys.verifying_key, commitment_list, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let group_commitment = match
    compute_group_commitment(ops, commitment_list, binding_factor_list) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let mut z = (ops.scalar_zero)()
  for i = 0; i < sig_shares.length(); i = i + 1 {
    z = (ops.scalar_add)(z, sig_shares[i].share)
  }
  let sig : Signature[S, E] = { r: group_commitment, z, }
  let valid = match prime_order_verify(ops, msg, sig, pub_keys.verifying_key) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if valid {
    return Ok(sig)
  }
  // RFC 9591 §5.4 Identifiable Abort (O(n) precomputed challenge & binding factors):
  // pinpoint every misbehaving participant without swallowing validation errors.
  let challenge = match
    compute_challenge(ops, group_commitment, pub_keys.verifying_key, msg) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let participant_list = participants_from_commitment_list(commitment_list)
  let cheaters : Array[Int32] = []
  for i = 0; i < num; i = i + 1 {
    let entry = commitment_list[i]
    let pk_i = match pub_keys.verifying_share_for(entry.identifier) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let mut share_opt : S? = None
    for j = 0; j < sig_shares.length(); j = j + 1 {
      if sig_shares[j].identifier == entry.identifier {
        share_opt = Some(sig_shares[j].share)
        break
      }
    }
    let share_i = match share_opt {
      Some(s) => s
      None => return Err(FrostError::InvalidParticipantId(entry.identifier))
    }
    let binding_factor = match
      binding_factor_for(binding_factor_list, entry.identifier) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let lambda_i = match
      derive_interpolating_value(ops, participant_list, entry.identifier) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let comm_share = (ops.element_add)(
      entry.commitments.hiding,
      (ops.scalar_mul_elem)(entry.commitments.binding, binding_factor),
    )
    let lhs = (ops.scalar_base_mul)(share_i)
    let rhs = (ops.element_add)(
      comm_share,
      (ops.scalar_mul_elem)(pk_i, (ops.scalar_mul)(challenge, lambda_i)),
    )
    if !(ops.element_eq)(lhs, rhs) {
      cheaters.push(entry.identifier)
    }
  }
  if cheaters.length() > 0 {
    Err(FrostError::CheaterDetected(sort_unique_ids(cheaters)))
  } else {
    Err(FrostError::InvalidSignature)
  }
}

///|
/// RFC 9591 Appendix A: canonical Schnorr signature encoding `R_encoded[Ne] || z_encoded[Ns]`.
pub fn[S, E] serialize_signature(
  ops : SuiteOps[S, E],
  sig : Signature[S, E],
) -> Result[Bytes, FrostError] {
  let r_enc = match serialize_element_checked(ops, sig.r) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let z_enc = (ops.serialize_scalar)(sig.z)
  Ok(@crypto.concat_bytes([r_enc, z_enc]))
}

///|
/// RFC 9591 Appendix A: strictly decodes `R_encoded[Ne] || z_encoded[Ns]`,
/// verifying exact length `Ne + Ns`, canonical non-identity `R`, and canonical `z`.
pub fn[S, E] deserialize_signature(
  ops : SuiteOps[S, E],
  bytes : Bytes,
) -> Result[Signature[S, E], FrostError] {
  let expected = ops.ne + ops.ns
  if bytes.length() != expected {
    return Err(FrostError::InvalidSignatureLength(bytes.length(), expected))
  }
  let r_bytes = Bytes::makei(ops.ne, fn(i) { bytes[i] })
  let z_bytes = Bytes::makei(ops.ns, fn(i) { bytes[ops.ne + i] })
  let r = match (ops.deserialize_element)(r_bytes) {
    Ok(v) => v
    Err(e) => return Err(FrostError::InvalidElement(e))
  }
  if (ops.element_is_identity)(r) {
    return Err(FrostError::IdentityElement)
  }
  let z = match (ops.deserialize_scalar)(z_bytes) {
    Ok(v) => v
    Err(e) => return Err(FrostError::InvalidScalar(e))
  }
  Ok({ r, z, })
}

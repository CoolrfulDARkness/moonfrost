///|
/// Decentralized Pedersen Distributed Key Generation (Komlo-Goldberg FROST Fig. 1)
/// with domain-separated Schnorr Proof of Knowledge (H_dkg) and identifiable
/// cheater detection in both Round 1 (PoK) and Round 2 (Feldman VSS shares).

///|
/// Private Round 1 DKG state held locally by a participant.
pub struct DkgRound1Secret[S] {
  priv identifier : Int32
  priv max_signers : Int32
  priv min_signers : Int32
  priv coeffs : Array[S]
}

///|
/// Public Round 1 DKG broadcast package containing Feldman VSS commitment and
/// Schnorr Proof of Knowledge of the constant term a_0.
#derive(Debug)
pub(all) struct DkgRound1Package[S, E] {
  identifier : Int32
  commitment : VssCommitment[E]
  pok_r : E
  pok_mu : S
}

///|
/// Private Round 2 DKG state held locally by a participant.
pub struct DkgRound2Secret[S, E] {
  priv identifier : Int32
  priv max_signers : Int32
  priv min_signers : Int32
  priv coeffs : Array[S]
  priv commitment : VssCommitment[E]
}

///|
/// Confidential Round 2 DKG secret share package sent from `sender` to `receiver`.
#derive(Debug)
pub(all) struct DkgRound2Package[S] {
  sender : Int32
  receiver : Int32
  secret_share : S
}

///|
fn[S, E] dkg_pok_challenge(
  ops : SuiteOps[S, E],
  identifier : Int32,
  c0 : E,
  pok_r : E,
) -> Result[S, FrostError] {
  let id_scalar = match id_to_scalar(ops, identifier) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let id_bytes = (ops.serialize_scalar)(id_scalar)
  let c0_bytes = match serialize_element_checked(ops, c0) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let r_bytes = match serialize_element_checked(ops, pok_r) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  Ok((ops.h_dkg)(@crypto.concat_bytes([id_bytes, c0_bytes, r_bytes])))
}

///|
fn[S, E] commitments_equal(
  ops : SuiteOps[S, E],
  a : VssCommitment[E],
  b : VssCommitment[E],
) -> Bool {
  if a.coeffs.length() != b.coeffs.length() {
    return false
  }
  for i = 0; i < a.coeffs.length(); i = i + 1 {
    if !(ops.element_eq)(a.coeffs[i], b.coeffs[i]) {
      return false
    }
  }
  true
}

///|
fn[S, E] validate_dkg_round1_packages(
  ops : SuiteOps[S, E],
  max_signers : Int32,
  min_signers : Int32,
  own_id : Int32,
  own_commitment : VssCommitment[E],
  round1_packages : Array[DkgRound1Package[S, E]],
) -> Result[Unit, FrostError] {
  let n = round1_packages.length()
  if n < max_signers {
    return Err(FrostError::InsufficientParticipants(n, max_signers))
  }
  if n > max_signers {
    return Err(
      FrostError::InvalidParameters("round1_packages count exceeds max_signers"),
    )
  }
  for i = 0; i < n; i = i + 1 {
    let pkg = round1_packages[i]
    if pkg.identifier <= 0 || pkg.identifier > max_signers {
      return Err(FrostError::InvalidParticipantId(pkg.identifier))
    }
    for j = i + 1; j < n; j = j + 1 {
      if round1_packages[j].identifier == pkg.identifier {
        return Err(FrostError::DuplicateParticipant(pkg.identifier))
      }
    }
    if pkg.commitment.coeffs.length() != min_signers {
      return Err(
        FrostError::InvalidVssCommitment(
          "DKG round1 commitment length does not match min_signers",
        ),
      )
    }
    if (ops.element_is_identity)(pkg.commitment.coeffs[0]) {
      return Err(FrostError::IdentityElement)
    }
    if pkg.identifier == own_id {
      if !commitments_equal(ops, pkg.commitment, own_commitment) {
        return Err(FrostError::CommitmentMismatch(own_id))
      }
    }
  }
  Ok(())
}

///|
/// Pedersen DKG Round 1: generates a random degree `min_signers - 1` polynomial,
/// computes its Feldman VSS commitment, and produces a domain-separated Schnorr
/// Proof of Knowledge of the constant term `a_0`.
pub fn[S, E] dkg_part1(
  ops : SuiteOps[S, E],
  identifier : Int32,
  max_signers : Int32,
  min_signers : Int32,
  drbg : @crypto.Drbg,
) -> Result[(DkgRound1Secret[S], DkgRound1Package[S, E]), FrostError] {
  match validate_threshold(min_signers, max_signers) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if identifier <= 0 || identifier > max_signers {
    return Err(FrostError::InvalidParticipantId(identifier))
  }
  let a0 = random_nonzero_scalar(ops, drbg)
  let coeffs : Array[S] = [a0]
  for _i = 1; _i < min_signers; _i = _i + 1 {
    coeffs.push(random_scalar(ops, drbg))
  }
  let commitment = vss_commit(ops, coeffs)
  let k = random_nonzero_scalar(ops, drbg)
  let pok_r = (ops.scalar_base_mul)(k)
  let c = match
    dkg_pok_challenge(ops, identifier, commitment.coeffs[0], pok_r) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let pok_mu = (ops.scalar_add)(k, (ops.scalar_mul)(a0, c))
  let secret : DkgRound1Secret[S] = {
    identifier,
    max_signers,
    min_signers,
    coeffs,
  }
  let pkg : DkgRound1Package[S, E] = { identifier, commitment, pok_r, pok_mu, }
  Ok((secret, pkg))
}

///|
/// Pedersen DKG Round 2: validates all `max_signers` Round 1 packages and their
/// Schnorr PoK proofs (returning `Err(InvalidDkgProof(cheater_ids))` if any fail),
/// then evaluates and returns secret share packages `f_i(j)` for all `j != i`.
pub fn[S, E] dkg_part2(
  ops : SuiteOps[S, E],
  secret : DkgRound1Secret[S],
  round1_packages : Array[DkgRound1Package[S, E]],
) -> Result[(DkgRound2Secret[S, E], Array[DkgRound2Package[S]]), FrostError] {
  let own_commitment = vss_commit(ops, secret.coeffs)
  match
    validate_dkg_round1_packages(
      ops,
      secret.max_signers,
      secret.min_signers,
      secret.identifier,
      own_commitment,
      round1_packages,
    ) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let bad_poks : Array[Int32] = []
  for i = 0; i < round1_packages.length(); i = i + 1 {
    let pkg = round1_packages[i]
    if (ops.element_is_identity)(pkg.pok_r) {
      bad_poks.push(pkg.identifier)
      continue
    }
    let c = match
      dkg_pok_challenge(
        ops,
        pkg.identifier,
        pkg.commitment.coeffs[0],
        pkg.pok_r,
      ) {
      Ok(v) => v
      Err(_) => {
        bad_poks.push(pkg.identifier)
        continue
      }
    }
    let lhs = (ops.scalar_base_mul)(pkg.pok_mu)
    let rhs = (ops.element_add)(
      pkg.pok_r,
      (ops.scalar_mul_elem)(pkg.commitment.coeffs[0], c),
    )
    if !(ops.element_eq)(lhs, rhs) {
      bad_poks.push(pkg.identifier)
    }
  }
  if bad_poks.length() > 0 {
    return Err(FrostError::InvalidDkgProof(sort_unique_ids(bad_poks)))
  }
  let out_packages : Array[DkgRound2Package[S]] = []
  for j = 1; j <= secret.max_signers; j = j + 1 {
    if j == secret.identifier {
      continue
    }
    let x_j = (ops.scalar_from_u32)(j.reinterpret_as_uint())
    let share = polynomial_evaluate(ops, x_j, secret.coeffs)
    out_packages.push({
      sender: secret.identifier,
      receiver: j,
      secret_share: share,
    })
  }
  let r2_secret : DkgRound2Secret[S, E] = {
    identifier: secret.identifier,
    max_signers: secret.max_signers,
    min_signers: secret.min_signers,
    coeffs: secret.coeffs,
    commitment: own_commitment,
  }
  Ok((r2_secret, out_packages))
}

///|
/// Pedersen DKG Round 3: verifies every received Round 2 secret share against
/// its sender's Feldman VSS commitment (returning `Err(CheaterDetected(ids))` on
/// any mismatch), then aggregates the participant's final signing share and the
/// shared group `PublicKeyPackage`.
pub fn[S, E] dkg_part3(
  ops : SuiteOps[S, E],
  secret : DkgRound2Secret[S, E],
  round1_packages : Array[DkgRound1Package[S, E]],
  round2_packages : Array[DkgRound2Package[S]],
) -> Result[(KeyPackage[S, E], PublicKeyPackage[E]), FrostError] {
  match
    validate_dkg_round1_packages(
      ops,
      secret.max_signers,
      secret.min_signers,
      secret.identifier,
      secret.commitment,
      round1_packages,
    ) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let expected_r2 = secret.max_signers - 1
  if round2_packages.length() < expected_r2 {
    return Err(
      FrostError::InsufficientParticipants(
        round2_packages.length(),
        expected_r2,
      ),
    )
  }
  if round2_packages.length() > expected_r2 {
    return Err(
      FrostError::InvalidParameters(
        "round2_packages count exceeds max_signers - 1",
      ),
    )
  }
  for i = 0; i < round2_packages.length(); i = i + 1 {
    let pkg = round2_packages[i]
    if pkg.receiver != secret.identifier {
      return Err(FrostError::InvalidParticipantId(pkg.receiver))
    }
    if pkg.sender <= 0 ||
      pkg.sender > secret.max_signers ||
      pkg.sender == secret.identifier {
      return Err(FrostError::InvalidParticipantId(pkg.sender))
    }
    for j = i + 1; j < round2_packages.length(); j = j + 1 {
      if round2_packages[j].sender == pkg.sender {
        return Err(FrostError::DuplicateParticipant(pkg.sender))
      }
    }
  }
  // Verify every received share f_j(i) against sender j's Round 1 VSS commitment.
  let cheaters : Array[Int32] = []
  for i = 0; i < round2_packages.length(); i = i + 1 {
    let pkg = round2_packages[i]
    let mut sender_comm : VssCommitment[E]? = None
    for j = 0; j < round1_packages.length(); j = j + 1 {
      if round1_packages[j].identifier == pkg.sender {
        sender_comm = Some(round1_packages[j].commitment)
        break
      }
    }
    let comm = match sender_comm {
      Some(c) => c
      None => return Err(FrostError::InvalidParticipantId(pkg.sender))
    }
    let ok = match vss_verify(ops, secret.identifier, pkg.secret_share, comm) {
      Ok(v) => v
      Err(_) => false
    }
    if !ok {
      cheaters.push(pkg.sender)
    }
  }
  if cheaters.length() > 0 {
    return Err(FrostError::CheaterDetected(sort_unique_ids(cheaters)))
  }
  // Aggregate secret signing share sk_i = f_i(i) + sum_{j != i} f_j(i).
  let own_x = (ops.scalar_from_u32)(secret.identifier.reinterpret_as_uint())
  let mut signing_share = polynomial_evaluate(ops, own_x, secret.coeffs)
  for i = 0; i < round2_packages.length(); i = i + 1 {
    signing_share = (ops.scalar_add)(
      signing_share,
      round2_packages[i].secret_share,
    )
  }
  // Aggregate group VSS commitment C_k = sum_{j=1..n} C_{j,k}.
  let group_coeffs : Array[E] = []
  for k = 0; k < secret.min_signers; k = k + 1 {
    let mut sum_k = (ops.element_identity)()
    for j = 0; j < round1_packages.length(); j = j + 1 {
      sum_k = (ops.element_add)(sum_k, round1_packages[j].commitment.coeffs[k])
    }
    group_coeffs.push(sum_k)
  }
  let group_commitment : VssCommitment[E] = { coeffs: group_coeffs, }
  let pub_pkg = match
    derive_group_info(
      ops,
      secret.max_signers,
      secret.min_signers,
      group_commitment,
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let verifying_share = (ops.scalar_base_mul)(signing_share)
  let expected_pk_i = match pub_pkg.verifying_share_for(secret.identifier) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if !(ops.element_eq)(verifying_share, expected_pk_i) {
    return Err(
      FrostError::InvalidVssCommitment(
        "aggregated signing share does not match derived verifying share",
      ),
    )
  }
  let key_pkg : KeyPackage[S, E] = {
    identifier: secret.identifier,
    signing_share,
    verifying_share,
    verifying_key: pub_pkg.verifying_key,
    min_signers: secret.min_signers,
    max_signers: secret.max_signers,
  }
  Ok((key_pkg, pub_pkg))
}

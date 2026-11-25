///|
/// 26 independent security & adversarial tests covering both RFC 9591 suites:
/// - FROST(ristretto255, SHA-512)
/// - FROST(P-256, SHA-256)

///|
fn adv_must_hex(hex : String) -> Bytes {
  match @crypto.hex_to_bytes(hex) {
    Ok(b) => b
    Err(e) => abort("invalid hex literal: \{e}")
  }
}

///|
fn adv_flip_byte(data : Bytes, idx : Int32, mask : Byte) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      data[i] ^ mask
    } else {
      data[i]
    }
  })
}

///|
fn[S, E] adv_setup_dealer(
  ops : @frost.SuiteOps[S, E],
  max_signers : Int32,
  min_signers : Int32,
  seed : String,
) -> (
  Array[@frost.KeyPackage[S, E]],
  @frost.PublicKeyPackage[E],
  @frost.VssCommitment[E],
) {
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes(seed))
  match @moonfrost.trusted_dealer_keygen(ops, drbg, max_signers, min_signers) {
    Ok(v) => v
    Err(e) => abort("trusted_dealer_keygen failed: \{e}")
  }
}

///|
fn[S, E] adv_round1_commit_subset(
  ops : @frost.SuiteOps[S, E],
  key_packages : Array[@frost.KeyPackage[S, E]],
  signer_ids : Array[Int32],
  seed : String,
) -> (Array[@frost.SigningNonces[S, E]], Array[@frost.CommitmentEntry[E]]) {
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes(seed))
  let nonces_list : Array[@frost.SigningNonces[S, E]] = []
  let comm_list : Array[@frost.CommitmentEntry[E]] = []
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let kp = key_packages[signer_ids[i] - 1]
    let (nonces, comms) = match @moonfrost.commit(ops, kp.signing_share, drbg) {
      Ok(v) => v
      Err(e) => abort("commit failed: \{e}")
    }
    nonces_list.push(nonces)
    comm_list.push(@frost.CommitmentEntry::new(kp.identifier, comms))
  }
  (nonces_list, comm_list)
}

///|
fn[S, E] adv_round2_sign_subset(
  ops : @frost.SuiteOps[S, E],
  key_packages : Array[@frost.KeyPackage[S, E]],
  signer_ids : Array[Int32],
  nonces_list : Array[@frost.SigningNonces[S, E]],
  comm_list : Array[@frost.CommitmentEntry[E]],
  msg : Bytes,
) -> Array[@frost.SignatureShare[S]] {
  let shares : Array[@frost.SignatureShare[S]] = []
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let kp = key_packages[signer_ids[i] - 1]
    let share = match @moonfrost.sign(ops, kp, nonces_list[i], msg, comm_list) {
      Ok(v) => v
      Err(e) => abort("sign failed: \{e}")
    }
    shares.push(share)
  }
  shares
}

///|
fn[S, E] adv_dkg_round1_all(
  ops : @frost.SuiteOps[S, E],
  max_signers : Int32,
  min_signers : Int32,
  seed_prefix : String,
) -> (Array[@frost.DkgRound1Secret[S]], Array[@frost.DkgRound1Package[S, E]]) {
  let secrets : Array[@frost.DkgRound1Secret[S]] = []
  let pkgs : Array[@frost.DkgRound1Package[S, E]] = []
  for id = 1; id <= max_signers; id = id + 1 {
    let drbg = @moonfrost.drbg_from_seed(
      @crypto.ascii_bytes("\{seed_prefix}-p\{id}"),
    )
    let (sec, pkg) = match
      @moonfrost.dkg_part1(ops, id, max_signers, min_signers, drbg) {
      Ok(v) => v
      Err(e) => abort("dkg_part1 failed: \{e}")
    }
    secrets.push(sec)
    pkgs.push(pkg)
  }
  (secrets, pkgs)
}

///|
fn[S, E] adv_dkg_round2_all(
  ops : @frost.SuiteOps[S, E],
  r1_secrets : Array[@frost.DkgRound1Secret[S]],
  r1_packages : Array[@frost.DkgRound1Package[S, E]],
) -> (
  Array[@frost.DkgRound2Secret[S, E]],
  Array[Array[@frost.DkgRound2Package[S]]],
) {
  let max_signers = r1_secrets.length()
  let r2_secrets : Array[@frost.DkgRound2Secret[S, E]] = []
  let inboxes : Array[Array[@frost.DkgRound2Package[S]]] = []
  for _i = 0; _i < max_signers; _i = _i + 1 {
    inboxes.push([])
  }
  for i = 0; i < max_signers; i = i + 1 {
    let (sec, out_pkgs) = match
      @moonfrost.dkg_part2(ops, r1_secrets[i], r1_packages) {
      Ok(v) => v
      Err(e) => abort("dkg_part2 failed: \{e}")
    }
    r2_secrets.push(sec)
    for j = 0; j < out_pkgs.length(); j = j + 1 {
      let pkg = out_pkgs[j]
      inboxes[pkg.receiver - 1].push(pkg)
    }
  }
  (r2_secrets, inboxes)
}

///|
test "adversarial_01_single_cheater_forged_share_ristretto255" {
  let ops = @moonfrost.ristretto255_sha512()
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "adv01-ristretto")
  let msg = @crypto.ascii_bytes("adv01-single-cheater")
  let signers : Array[Int32] = [1, 3]
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, signers, "adv01-r1")
  let shares = adv_round2_sign_subset(ops, kps, signers, nonces, comms, msg)
  let forged : Array[@frost.SignatureShare[@ristretto255.Scalar]] = [
    shares[0],
    {
      identifier: shares[1].identifier,
      share: (ops.scalar_add)(shares[1].share, (ops.scalar_one)()),
    },
  ]
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, forged) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [3])
    Err(e) => fail("expected CheaterDetected([3]), got \{e}")
    Ok(_) => fail("expected CheaterDetected([3]), got Ok")
  }
}

///|
test "adversarial_02_single_cheater_forged_share_p256" {
  let ops = @moonfrost.p256_sha256()
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "adv02-p256")
  let msg = @crypto.ascii_bytes("adv02-single-cheater")
  let signers : Array[Int32] = [1, 3]
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, signers, "adv02-r1")
  let shares = adv_round2_sign_subset(ops, kps, signers, nonces, comms, msg)
  let forged : Array[@frost.SignatureShare[@p256.Scalar]] = [
    {
      identifier: shares[0].identifier,
      share: (ops.scalar_add)(shares[0].share, (ops.scalar_one)()),
    },
    shares[1],
  ]
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, forged) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [1])
    Err(e) => fail("expected CheaterDetected([1]), got \{e}")
    Ok(_) => fail("expected CheaterDetected([1]), got Ok")
  }
}

///|
fn[S, E] check_colluding_cheaters_3of5(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 5, 3, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let signers : Array[Int32] = [1, 2, 4]
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, signers, "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps, signers, nonces, comms, msg)
  // Both P2 and P4 forge their shares with non-canceling deltas
  let forged : Array[@frost.SignatureShare[S]] = [
    shares[0],
    {
      identifier: 2,
      share: (ops.scalar_add)(shares[1].share, (ops.scalar_from_u32)(3U)),
    },
    {
      identifier: 4,
      share: (ops.scalar_add)(shares[2].share, (ops.scalar_from_u32)(5U)),
    },
  ]
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, forged) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [2, 4])
    Err(e) => fail("\{tag}: expected CheaterDetected([2, 4]), got \{e}")
    Ok(_) => fail("\{tag}: expected CheaterDetected([2, 4]), got Ok")
  }
}

///|
test "adversarial_03_colluding_multiple_cheaters_3of5_both_suites" {
  check_colluding_cheaters_3of5(@moonfrost.ristretto255_sha512(), "adv03-r255")
  check_colluding_cheaters_3of5(@moonfrost.p256_sha256(), "adv03-p256")
}

///|
fn[S, E] check_share_identity_swap(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-swap")
  let signers : Array[Int32] = [1, 3]
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, signers, "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps, signers, nonces, comms, msg)
  // Attach P1's signature share to P3's participant ID
  let mismatched : Array[@frost.SignatureShare[S]] = [
    shares[0],
    { identifier: 3, share: shares[0].share, },
  ]
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, mismatched) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [3])
    Err(e) => fail("\{tag}: expected CheaterDetected([3]), got \{e}")
    Ok(_) => fail("\{tag}: expected CheaterDetected([3]), got Ok")
  }
  assert_eq(
    @moonfrost.verify_signature_share(
      ops,
      3,
      kps[2].verifying_share,
      comms[1].commitments,
      shares[0].share,
      comms,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(false),
  )
}

///|
test "adversarial_04_signature_share_identity_swap_both_suites" {
  check_share_identity_swap(@moonfrost.ristretto255_sha512(), "adv04-r255")
  check_share_identity_swap(@moonfrost.p256_sha256(), "adv04-p256")
}

///|
fn[S, E] check_tampered_own_hiding_commitment(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, _, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let bad_hiding = (ops.element_add)(
    comms[0].commitments.hiding,
    (ops.element_generator)(),
  )
  let tampered_comms : Array[@frost.CommitmentEntry[E]] = [
    @frost.CommitmentEntry::new(1, {
      hiding: bad_hiding,
      binding: comms[0].commitments.binding,
    }),
    comms[1],
  ]
  match @moonfrost.sign(ops, kps[0], nonces[0], msg, tampered_comms) {
    Err(@frost.FrostError::CommitmentMismatch(id)) => assert_eq(id, 1)
    Err(e) => fail("\{tag}: expected CommitmentMismatch(1), got \{e}")
    Ok(_) => fail("\{tag}: expected CommitmentMismatch(1), got Ok")
  }
  assert_false(nonces[0].is_used())
}

///|
test "adversarial_05_tampered_own_hiding_commitment" {
  check_tampered_own_hiding_commitment(
    @moonfrost.ristretto255_sha512(),
    "adv05-r255",
  )
  check_tampered_own_hiding_commitment(@moonfrost.p256_sha256(), "adv05-p256")
}

///|
fn[S, E] check_tampered_own_binding_commitment(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, _, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let bad_binding = (ops.element_add)(
    comms[0].commitments.binding,
    (ops.element_generator)(),
  )
  let tampered_comms : Array[@frost.CommitmentEntry[E]] = [
    @frost.CommitmentEntry::new(1, {
      hiding: comms[0].commitments.hiding,
      binding: bad_binding,
    }),
    comms[1],
  ]
  match @moonfrost.sign(ops, kps[0], nonces[0], msg, tampered_comms) {
    Err(@frost.FrostError::CommitmentMismatch(id)) => assert_eq(id, 1)
    Err(e) => fail("\{tag}: expected CommitmentMismatch(1), got \{e}")
    Ok(_) => fail("\{tag}: expected CommitmentMismatch(1), got Ok")
  }
  assert_false(nonces[0].is_used())
}

///|
test "adversarial_06_tampered_own_binding_commitment" {
  check_tampered_own_binding_commitment(
    @moonfrost.ristretto255_sha512(),
    "adv06-r255",
  )
  check_tampered_own_binding_commitment(@moonfrost.p256_sha256(), "adv06-p256")
}

///|
fn[S, E] check_tampered_peer_commitment(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  // P1 signs honestly with `comms`, P3 receives a tampered peer commitment for P1
  let bad_p1_hiding = (ops.element_add)(
    comms[0].commitments.hiding,
    (ops.element_generator)(),
  )
  let tampered_comms : Array[@frost.CommitmentEntry[E]] = [
    @frost.CommitmentEntry::new(1, {
      hiding: bad_p1_hiding,
      binding: comms[0].commitments.binding,
    }),
    comms[1],
  ]
  let s1 = match @moonfrost.sign(ops, kps[0], nonces[0], msg, comms) {
    Ok(v) => v
    Err(e) => fail("\{tag}: honest p1 sign failed: \{e}")
  }
  let s3 = match @moonfrost.sign(ops, kps[2], nonces[1], msg, tampered_comms) {
    Ok(v) => v
    Err(e) => fail("\{tag}: p3 sign under tampered peer comm failed: \{e}")
  }
  // Coordinator aggregates against canonical `comms`: P3's share fails verification
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, [s1, s3]) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [3])
    Err(e) => fail("\{tag}: expected CheaterDetected([3]), got \{e}")
    Ok(_) => fail("\{tag}: expected CheaterDetected([3]), got Ok")
  }
  // Coordinator aggregates against `tampered_comms`: P1's share fails verification
  match @moonfrost.aggregate(ops, tampered_comms, msg, pub_pkg, [s1, s3]) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [1])
    Err(e) => fail("\{tag}: expected CheaterDetected([1]), got \{e}")
    Ok(_) => fail("\{tag}: expected CheaterDetected([1]), got Ok")
  }
}

///|
test "adversarial_07_tampered_peer_commitment" {
  check_tampered_peer_commitment(@moonfrost.ristretto255_sha512(), "adv07-r255")
  check_tampered_peer_commitment(@moonfrost.p256_sha256(), "adv07-p256")
}

///|
fn[S, E] check_insufficient_participants_sign(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, _, _) = adv_setup_dealer(ops, 5, 3, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 2], "\{tag}-r1")
  match @moonfrost.sign(ops, kps[0], nonces[0], msg, comms) {
    Err(@frost.FrostError::InsufficientParticipants(actual, needed)) => {
      assert_eq(actual, 2)
      assert_eq(needed, 3)
    }
    Err(e) => fail("\{tag}: expected InsufficientParticipants(2, 3), got \{e}")
    Ok(_) => fail("\{tag}: expected InsufficientParticipants(2, 3), got Ok")
  }
  assert_false(nonces[0].is_used())
}

///|
test "adversarial_08_insufficient_participants_sign" {
  check_insufficient_participants_sign(
    @moonfrost.ristretto255_sha512(),
    "adv08-r255",
  )
  check_insufficient_participants_sign(@moonfrost.p256_sha256(), "adv08-p256")
}

///|
fn[S, E] check_insufficient_participants_aggregate(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps, [1, 3], nonces, comms, msg)
  // Case A: fewer than t entries in commitment_list
  match @moonfrost.aggregate(ops, [comms[0]], msg, pub_pkg, [shares[0]]) {
    Err(@frost.FrostError::InsufficientParticipants(actual, needed)) => {
      assert_eq(actual, 1)
      assert_eq(needed, 2)
    }
    Err(e) => fail("\{tag}: expected InsufficientParticipants(1, 2), got \{e}")
    Ok(_) => fail("\{tag}: expected InsufficientParticipants(1, 2), got Ok")
  }
  // Case B: valid commitment_list but fewer sig_shares than commitments
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, [shares[0]]) {
    Err(@frost.FrostError::InsufficientParticipants(actual, needed)) => {
      assert_eq(actual, 1)
      assert_eq(needed, 2)
    }
    Err(e) => fail("\{tag}: expected InsufficientParticipants(1, 2), got \{e}")
    Ok(_) => fail("\{tag}: expected InsufficientParticipants(1, 2), got Ok")
  }
}

///|
test "adversarial_09_insufficient_participants_aggregate" {
  check_insufficient_participants_aggregate(
    @moonfrost.ristretto255_sha512(),
    "adv09-r255",
  )
  check_insufficient_participants_aggregate(
    @moonfrost.p256_sha256(),
    "adv09-p256",
  )
}

///|
fn[S, E] check_insufficient_shares_combine(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, _, _) = adv_setup_dealer(ops, 5, 3, "\{tag}-dealer")
  match
    @frost.secret_share_combine(
      ops,
      [(1, kps[0].signing_share), (2, kps[1].signing_share)],
      3,
    ) {
    Err(@frost.FrostError::InsufficientParticipants(actual, needed)) => {
      assert_eq(actual, 2)
      assert_eq(needed, 3)
    }
    Err(e) => fail("\{tag}: expected InsufficientParticipants(2, 3), got \{e}")
    Ok(_) => fail("\{tag}: expected InsufficientParticipants(2, 3), got Ok")
  }
}

///|
test "adversarial_10_insufficient_shares_secret_combine" {
  check_insufficient_shares_combine(
    @moonfrost.ristretto255_sha512(),
    "adv10-r255",
  )
  check_insufficient_shares_combine(@moonfrost.p256_sha256(), "adv10-p256")
}

///|
fn[S, E] check_duplicate_commitment_list(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let dup_comms : Array[@frost.CommitmentEntry[E]] = [comms[0], comms[0]]
  assert_eq(
    @frost.validate_commitment_list(ops, dup_comms, 2),
    Err(@frost.FrostError::DuplicateParticipant(1)),
  )
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, dup_comms)
    is Err(@frost.FrostError::DuplicateParticipant(1)),
  )
  let dummy_shares : Array[@frost.SignatureShare[S]] = [
    { identifier: 1, share: (ops.scalar_one)(), },
    { identifier: 3, share: (ops.scalar_one)(), },
  ]
  assert_true(
    @moonfrost.aggregate(ops, dup_comms, msg, pub_pkg, dummy_shares)
    is Err(@frost.FrostError::DuplicateParticipant(1)),
  )
}

///|
test "adversarial_11_duplicate_participant_commitment_list" {
  check_duplicate_commitment_list(
    @moonfrost.ristretto255_sha512(),
    "adv11-r255",
  )
  check_duplicate_commitment_list(@moonfrost.p256_sha256(), "adv11-p256")
}

///|
fn[S, E] check_duplicate_sig_shares(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps, [1, 3], nonces, comms, msg)
  let dup_shares : Array[@frost.SignatureShare[S]] = [shares[0], shares[0]]
  match @moonfrost.aggregate(ops, comms, msg, pub_pkg, dup_shares) {
    Err(@frost.FrostError::DuplicateParticipant(id)) => assert_eq(id, 1)
    Err(e) => fail("\{tag}: expected DuplicateParticipant(1), got \{e}")
    Ok(_) => fail("\{tag}: expected DuplicateParticipant(1), got Ok")
  }
}

///|
test "adversarial_12_duplicate_participant_sig_shares" {
  check_duplicate_sig_shares(@moonfrost.ristretto255_sha512(), "adv12-r255")
  check_duplicate_sig_shares(@moonfrost.p256_sha256(), "adv12-p256")
}

///|
fn[S, E] check_unsorted_commitments(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let unsorted : Array[@frost.CommitmentEntry[E]] = [comms[1], comms[0]]
  assert_eq(
    @frost.validate_commitment_list(ops, unsorted, 2),
    Err(@frost.FrostError::UnsortedCommitments),
  )
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, unsorted)
    is Err(@frost.FrostError::UnsortedCommitments),
  )
  let dummy_shares : Array[@frost.SignatureShare[S]] = [
    { identifier: 1, share: (ops.scalar_one)(), },
    { identifier: 3, share: (ops.scalar_one)(), },
  ]
  assert_true(
    @moonfrost.aggregate(ops, unsorted, msg, pub_pkg, dummy_shares)
    is Err(@frost.FrostError::UnsortedCommitments),
  )
}

///|
test "adversarial_13_unsorted_commitment_list" {
  check_unsorted_commitments(@moonfrost.ristretto255_sha512(), "adv13-r255")
  check_unsorted_commitments(@moonfrost.p256_sha256(), "adv13-p256")
}

///|
fn[S, E] check_invalid_participant_ids(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, vss_comm) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-drbg"))
  let (_, c1) = match @moonfrost.commit(ops, kps[0].signing_share, drbg) {
    Ok(v) => v
    Err(e) => fail("\{tag}: commit failed: \{e}")
  }
  let (_, c2) = match @moonfrost.commit(ops, kps[1].signing_share, drbg) {
    Ok(v) => v
    Err(e) => fail("\{tag}: commit failed: \{e}")
  }
  // ID 0 and -1 in commitment_list
  assert_eq(
    @frost.validate_commitment_list(
      ops,
      [@frost.CommitmentEntry::new(0, c1), @frost.CommitmentEntry::new(1, c2)],
      2,
    ),
    Err(@frost.FrostError::InvalidParticipantId(0)),
  )
  assert_eq(
    @frost.validate_commitment_list(
      ops,
      [@frost.CommitmentEntry::new(-1, c1), @frost.CommitmentEntry::new(1, c2)],
      2,
    ),
    Err(@frost.FrostError::InvalidParticipantId(-1)),
  )
  // ID 0 and -1 in DKG Round 1
  assert_true(
    @moonfrost.dkg_part1(ops, 0, 3, 2, drbg)
    is Err(@frost.FrostError::InvalidParticipantId(0)),
  )
  assert_true(
    @moonfrost.dkg_part1(ops, -1, 3, 2, drbg)
    is Err(@frost.FrostError::InvalidParticipantId(-1)),
  )
  // ID 0 and -1 in Lagrange interpolation & Feldman VSS & pub_pkg lookup
  assert_true(
    @frost.derive_interpolating_value(ops, [0, 1], 0)
    is Err(@frost.FrostError::InvalidParticipantId(0)),
  )
  assert_true(
    @frost.derive_interpolating_value(ops, [-1, 1], -1)
    is Err(@frost.FrostError::InvalidParticipantId(-1)),
  )
  assert_eq(
    @frost.vss_verify(ops, 0, kps[0].signing_share, vss_comm),
    Err(@frost.FrostError::InvalidParticipantId(0)),
  )
  assert_eq(
    @frost.vss_verify(ops, -1, kps[0].signing_share, vss_comm),
    Err(@frost.FrostError::InvalidParticipantId(-1)),
  )
  assert_true(
    pub_pkg.verifying_share_for(0)
    is Err(@frost.FrostError::InvalidParticipantId(0)),
  )
  assert_true(
    pub_pkg.verifying_share_for(-1)
    is Err(@frost.FrostError::InvalidParticipantId(-1)),
  )
}

///|
test "adversarial_14_invalid_participant_ids" {
  check_invalid_participant_ids(@moonfrost.ristretto255_sha512(), "adv14-r255")
  check_invalid_participant_ids(@moonfrost.p256_sha256(), "adv14-p256")
}

///|
test "adversarial_15_nonce_reuse_attack_ristretto255" {
  let ops = @moonfrost.ristretto255_sha512()
  let (kps, _, _) = adv_setup_dealer(ops, 3, 2, "adv15-r255")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "adv15-r1")
  let msg1 = @crypto.ascii_bytes("message-one")
  let msg2 = @crypto.ascii_bytes("message-two")
  assert_false(nonces[0].is_used())
  assert_true(@moonfrost.sign(ops, kps[0], nonces[0], msg1, comms) is Ok(_))
  assert_true(nonces[0].is_used())
  // Second sign on SAME message must be rejected
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg1, comms)
    is Err(@frost.FrostError::NonceAlreadyUsed),
  )
  // Third sign on DIFFERENT message must also be rejected
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg2, comms)
    is Err(@frost.FrostError::NonceAlreadyUsed),
  )
}

///|
test "adversarial_16_nonce_reuse_attack_p256" {
  let ops = @moonfrost.p256_sha256()
  let (kps, _, _) = adv_setup_dealer(ops, 3, 2, "adv16-p256")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "adv16-r1")
  let msg1 = @crypto.ascii_bytes("p256-message-one")
  let msg2 = @crypto.ascii_bytes("p256-message-two")
  assert_false(nonces[0].is_used())
  assert_true(@moonfrost.sign(ops, kps[0], nonces[0], msg1, comms) is Ok(_))
  assert_true(nonces[0].is_used())
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg1, comms)
    is Err(@frost.FrostError::NonceAlreadyUsed),
  )
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg2, comms)
    is Err(@frost.FrostError::NonceAlreadyUsed),
  )
}

///|
test "adversarial_17_noncanonical_ristretto255_element_encodings" {
  let ops = @moonfrost.ristretto255_sha512()
  let invalid_encodings : Array[String] = [
    // High bit non-zero
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // >= p (2^255 - 19 = edffff...7f)
     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // Odd / negative field elements
     "0100000000000000000000000000000000000000000000000000000000000000", "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // Non-square x^2
     "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371", "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
    // Negative x * y
     "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
    // s = -1 causing y = 0
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // Wrong lengths (31 bytes & 33 bytes)
     "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d", "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d7600",
  ]
  for i = 0; i < invalid_encodings.length(); i = i + 1 {
    let raw = adv_must_hex(invalid_encodings[i])
    assert_true(@ristretto255.RistrettoPoint::decode(raw) is Err(_))
    assert_true(
      @ristretto255.RistrettoPoint::deserialize_non_identity(raw) is Err(_),
    )
    assert_true((ops.deserialize_element)(raw) is Err(_))
  }
  // 32-byte all-zero identity must be rejected by non-identity deserialization
  let zero32 = adv_must_hex(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_true(
    @ristretto255.RistrettoPoint::deserialize_non_identity(zero32) is Err(_),
  )
  assert_true((ops.deserialize_element)(zero32) is Err(_))
}

///|
test "adversarial_18_noncanonical_p256_sec1_element_encodings" {
  let ops = @moonfrost.p256_sha256()
  let invalid_encodings : Array[String] = [
    // Uncompressed prefix 0x04 (both 65-byte SEC1 uncompressed G and 33-byte)
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    // Identity encoding 0x00 (1-byte and 33-byte)
     "00", "000000000000000000000000000000000000000000000000000000000000000000",
    // Invalid prefix 0x05, 0x01, 0x06
     "056b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "016b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "066b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    // x >= p (x == p, x == p + 1, x == 0xff*32)
     "02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", "02ffffffff00000001000000000000000000000001000000000000000000000000",
    "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // x not on P-256 curve (x = 1 yields non-quadratic-residue RHS)
     "020000000000000000000000000000000000000000000000000000000000000001", "030000000000000000000000000000000000000000000000000000000000000001",
    // Truncated (32 bytes) and overlong (34 bytes)
     "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2", "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29600",
  ]
  for i = 0; i < invalid_encodings.length(); i = i + 1 {
    let raw = adv_must_hex(invalid_encodings[i])
    assert_true(@p256.P256Point::deserialize_compressed(raw) is Err(_))
    assert_true((ops.deserialize_element)(raw) is Err(_))
  }
}

///|
test "adversarial_19_noncanonical_scalar_encodings_both_suites" {
  // Ristretto255 scalar order L (little-endian):
  // L = edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010
  let r255_ops = @moonfrost.ristretto255_sha512()
  assert_true(
    @ristretto255.Scalar::from_bytes_strict(
      adv_must_hex(
        "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
      ),
    )
    is Ok(_),
  )
  let r255_bad_scalars : Array[String] = [
    // == L
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    // == L + 1
     "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    // 0xff * 32
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // Wrong lengths (0, 31, 33 bytes)
     "", "01000000000000000000000000000000000000000000000000000000000000", "010000000000000000000000000000000000000000000000000000000000000000",
  ]
  for i = 0; i < r255_bad_scalars.length(); i = i + 1 {
    let raw = adv_must_hex(r255_bad_scalars[i])
    assert_true(@ristretto255.Scalar::from_bytes_strict(raw) is Err(_))
    assert_true((r255_ops.deserialize_scalar)(raw) is Err(_))
  }

  // P-256 scalar order n (big-endian):
  // n = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  let p256_ops = @moonfrost.p256_sha256()
  assert_true(
    @p256.Scalar::from_bytes_strict(
      adv_must_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
      ),
    )
    is Ok(_),
  )
  let p256_bad_scalars : Array[String] = [
    // == n
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    // == n + 1
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    // 0xff * 32
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // Wrong lengths (0, 31, 33 bytes)
     "", "00000000000000000000000000000000000000000000000000000000000001", "000000000000000000000000000000000000000000000000000000000000000100",
  ]
  for i = 0; i < p256_bad_scalars.length(); i = i + 1 {
    let raw = adv_must_hex(p256_bad_scalars[i])
    assert_true(@p256.Scalar::from_bytes_strict(raw) is Err(_))
    assert_true((p256_ops.deserialize_scalar)(raw) is Err(_))
  }
}

///|
fn[S, E] check_identity_injection(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let id_elem = (ops.element_identity)()
  // Inject identity into peer's hiding commitment
  let bad_hiding_list : Array[@frost.CommitmentEntry[E]] = [
    comms[0],
    @frost.CommitmentEntry::new(3, {
      hiding: id_elem,
      binding: comms[1].commitments.binding,
    }),
  ]
  assert_eq(
    @frost.validate_commitment_list(ops, bad_hiding_list, 2),
    Err(@frost.FrostError::IdentityElement),
  )
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, bad_hiding_list)
    is Err(@frost.FrostError::IdentityElement),
  )
  let dummy_shares : Array[@frost.SignatureShare[S]] = [
    { identifier: 1, share: (ops.scalar_one)(), },
    { identifier: 3, share: (ops.scalar_one)(), },
  ]
  assert_true(
    @moonfrost.aggregate(ops, bad_hiding_list, msg, pub_pkg, dummy_shares)
    is Err(@frost.FrostError::IdentityElement),
  )

  // Inject identity into peer's binding commitment
  let bad_binding_list : Array[@frost.CommitmentEntry[E]] = [
    comms[0],
    @frost.CommitmentEntry::new(3, {
      hiding: comms[1].commitments.hiding,
      binding: id_elem,
    }),
  ]
  assert_eq(
    @frost.validate_commitment_list(ops, bad_binding_list, 2),
    Err(@frost.FrostError::IdentityElement),
  )
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, bad_binding_list)
    is Err(@frost.FrostError::IdentityElement),
  )
  assert_true(
    @moonfrost.aggregate(ops, bad_binding_list, msg, pub_pkg, dummy_shares)
    is Err(@frost.FrostError::IdentityElement),
  )

  // Identity R or identity public key in prime_order_verify
  let id_r_sig : @frost.Signature[S, E] = { r: id_elem, z: (ops.scalar_one)(), }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg, id_r_sig, pub_pkg.verifying_key),
    Err(@frost.FrostError::IdentityElement),
  )
  let gen_sig : @frost.Signature[S, E] = {
    r: (ops.element_generator)(),
    z: (ops.scalar_one)(),
  }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg, gen_sig, id_elem),
    Err(@frost.FrostError::IdentityElement),
  )
}

///|
test "adversarial_20_identity_element_injection_both_suites" {
  check_identity_injection(@moonfrost.ristretto255_sha512(), "adv20-r255")
  check_identity_injection(@moonfrost.p256_sha256(), "adv20-p256")
}

///|
fn[S, E] check_dkg_r1_forged_pok(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (r1_secrets, r1_pkgs) = adv_dkg_round1_all(ops, 5, 3, "\{tag}-dkg")
  // Forge P3's Schnorr PoK scalar mu
  let bad_mu_pkgs : Array[@frost.DkgRound1Package[S, E]] = []
  for i = 0; i < r1_pkgs.length(); i = i + 1 {
    let p = r1_pkgs[i]
    if p.identifier == 3 {
      bad_mu_pkgs.push({
        identifier: p.identifier,
        commitment: p.commitment,
        pok_r: p.pok_r,
        pok_mu: (ops.scalar_add)(p.pok_mu, (ops.scalar_one)()),
      })
    } else {
      bad_mu_pkgs.push(p)
    }
  }
  match @moonfrost.dkg_part2(ops, r1_secrets[0], bad_mu_pkgs) {
    Err(@frost.FrostError::InvalidDkgProof(ids)) => assert_eq(ids, [3])
    Err(e) => fail("\{tag}: expected InvalidDkgProof([3]), got \{e}")
    Ok(_) => fail("\{tag}: expected InvalidDkgProof([3]), got Ok")
  }
  // Forge P4's PoK nonce R as identity element
  let bad_r_pkgs : Array[@frost.DkgRound1Package[S, E]] = []
  for i = 0; i < r1_pkgs.length(); i = i + 1 {
    let p = r1_pkgs[i]
    if p.identifier == 4 {
      bad_r_pkgs.push({
        identifier: p.identifier,
        commitment: p.commitment,
        pok_r: (ops.element_identity)(),
        pok_mu: p.pok_mu,
      })
    } else {
      bad_r_pkgs.push(p)
    }
  }
  match @moonfrost.dkg_part2(ops, r1_secrets[0], bad_r_pkgs) {
    Err(@frost.FrostError::InvalidDkgProof(ids)) => assert_eq(ids, [4])
    Err(e) => fail("\{tag}: expected InvalidDkgProof([4]), got \{e}")
    Ok(_) => fail("\{tag}: expected InvalidDkgProof([4]), got Ok")
  }
}

///|
test "adversarial_21_pedersen_dkg_r1_forged_pok_both_suites" {
  check_dkg_r1_forged_pok(@moonfrost.ristretto255_sha512(), "adv21-r255")
  check_dkg_r1_forged_pok(@moonfrost.p256_sha256(), "adv21-p256")
}

///|
fn[S, E] check_dkg_r2_forged_share(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (r1_secrets, r1_pkgs) = adv_dkg_round1_all(ops, 5, 3, "\{tag}-dkg")
  let (r2_secrets, inboxes) = adv_dkg_round2_all(ops, r1_secrets, r1_pkgs)
  // Sender P3 sends a forged secret share to P1
  let bad_inbox : Array[@frost.DkgRound2Package[S]] = []
  for i = 0; i < inboxes[0].length(); i = i + 1 {
    let pkg = inboxes[0][i]
    if pkg.sender == 3 {
      bad_inbox.push({
        sender: pkg.sender,
        receiver: pkg.receiver,
        secret_share: (ops.scalar_add)(pkg.secret_share, (ops.scalar_one)()),
      })
    } else {
      bad_inbox.push(pkg)
    }
  }
  match @moonfrost.dkg_part3(ops, r2_secrets[0], r1_pkgs, bad_inbox) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [3])
    Err(e) => fail("\{tag}: expected CheaterDetected([3]), got \{e}")
    Ok(_) => fail("\{tag}: expected CheaterDetected([3]), got Ok")
  }
}

///|
test "adversarial_22_pedersen_dkg_r2_forged_share_both_suites" {
  check_dkg_r2_forged_share(@moonfrost.ristretto255_sha512(), "adv22-r255")
  check_dkg_r2_forged_share(@moonfrost.p256_sha256(), "adv22-p256")
}

///|
fn[S, E] check_dkg_r2_multi_cheaters(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (r1_secrets, r1_pkgs) = adv_dkg_round1_all(ops, 5, 3, "\{tag}-dkg")
  let (r2_secrets, inboxes) = adv_dkg_round2_all(ops, r1_secrets, r1_pkgs)
  // Both P2 and P4 simultaneously send bad shares to P1
  let bad_inbox : Array[@frost.DkgRound2Package[S]] = []
  for i = 0; i < inboxes[0].length(); i = i + 1 {
    let pkg = inboxes[0][i]
    if pkg.sender == 2 || pkg.sender == 4 {
      bad_inbox.push({
        sender: pkg.sender,
        receiver: pkg.receiver,
        secret_share: (ops.scalar_add)(pkg.secret_share, (ops.scalar_one)()),
      })
    } else {
      bad_inbox.push(pkg)
    }
  }
  match @moonfrost.dkg_part3(ops, r2_secrets[0], r1_pkgs, bad_inbox) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [2, 4])
    Err(e) => fail("\{tag}: expected CheaterDetected([2, 4]), got \{e}")
    Ok(_) => fail("\{tag}: expected CheaterDetected([2, 4]), got Ok")
  }
}

///|
test "adversarial_23_pedersen_dkg_r2_multiple_cheaters_both_suites" {
  check_dkg_r2_multi_cheaters(@moonfrost.ristretto255_sha512(), "adv23-r255")
  check_dkg_r2_multi_cheaters(@moonfrost.p256_sha256(), "adv23-p256")
}

///|
fn[S, E] check_feldman_vss_tampered_share(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, _, vss_comm) = adv_setup_dealer(ops, 5, 3, "\{tag}-dealer")
  for i = 0; i < kps.length(); i = i + 1 {
    let kp = kps[i]
    assert_eq(
      @frost.vss_verify(ops, kp.identifier, kp.signing_share, vss_comm),
      Ok(true),
    )
    let bad_share = (ops.scalar_add)(kp.signing_share, (ops.scalar_one)())
    assert_eq(
      @frost.vss_verify(ops, kp.identifier, bad_share, vss_comm),
      Ok(false),
    )
  }
}

///|
test "adversarial_24_feldman_vss_tampered_share_detection" {
  check_feldman_vss_tampered_share(
    @moonfrost.ristretto255_sha512(),
    "adv24-r255",
  )
  check_feldman_vss_tampered_share(@moonfrost.p256_sha256(), "adv24-p256")
}

///|
fn[S, E] check_signature_replay_bitflip_and_length(
  ops : @frost.SuiteOps[S, E],
  expected_sig_len : Int32,
  tag : String,
) -> Unit raise {
  let (kps1, pub1, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-group1")
  let (_, pub2, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-group2")
  let msg1 = @crypto.ascii_bytes("\{tag}-original-msg")
  let msg2 = @crypto.ascii_bytes("\{tag}-replayed-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps1, [1, 3], "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps1, [1, 3], nonces, comms, msg1)
  let sig = match @moonfrost.aggregate(ops, comms, msg1, pub1, shares) {
    Ok(v) => v
    Err(e) => fail("\{tag}: aggregate failed: \{e}")
  }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg1, sig, pub1.verifying_key),
    Ok(true),
  )

  // Cross-message replay must fail
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg2, sig, pub1.verifying_key),
    Ok(false),
  )

  // Cross-public-key verification must fail
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg1, sig, pub2.verifying_key),
    Ok(false),
  )

  // Algebraic perturbation of R and z must fail verification
  let bad_r_sig : @frost.Signature[S, E] = {
    r: (ops.element_add)(sig.r, (ops.element_generator)()),
    z: sig.z,
  }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg1, bad_r_sig, pub1.verifying_key),
    Ok(false),
  )
  let bad_z_sig : @frost.Signature[S, E] = {
    r: sig.r,
    z: (ops.scalar_add)(sig.z, (ops.scalar_one)()),
  }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg1, bad_z_sig, pub1.verifying_key),
    Ok(false),
  )

  // Wire-level bit-flip in R and in z must either fail canonical decode or fail verify
  let sig_bytes = match @moonfrost.serialize_signature(ops, sig) {
    Ok(b) => b
    Err(e) => fail("\{tag}: serialize_signature failed: \{e}")
  }
  assert_eq(sig_bytes.length(), expected_sig_len)

  let flipped_r_bytes = adv_flip_byte(sig_bytes, 1, b'\x01')
  match @moonfrost.deserialize_signature(ops, flipped_r_bytes) {
    Err(@frost.FrostError::InvalidElement(_)) => ()
    Err(e) => fail("\{tag}: expected InvalidElement on R bit-flip, got \{e}")
    Ok(s) =>
      assert_eq(
        @moonfrost.prime_order_verify(ops, msg1, s, pub1.verifying_key),
        Ok(false),
      )
  }
  let flipped_z_bytes = adv_flip_byte(sig_bytes, expected_sig_len - 1, b'\x01')
  match @moonfrost.deserialize_signature(ops, flipped_z_bytes) {
    Err(@frost.FrostError::InvalidScalar(_)) => ()
    Err(e) => fail("\{tag}: expected InvalidScalar on z bit-flip, got \{e}")
    Ok(s) =>
      assert_eq(
        @moonfrost.prime_order_verify(ops, msg1, s, pub1.verifying_key),
        Ok(false),
      )
  }

  // Truncated and overlong signature bytes must fail with InvalidSignatureLength
  let truncated = Bytes::makei(expected_sig_len - 1, fn(i) { sig_bytes[i] })
  match @moonfrost.deserialize_signature(ops, truncated) {
    Err(@frost.FrostError::InvalidSignatureLength(actual, expected)) => {
      assert_eq(actual, expected_sig_len - 1)
      assert_eq(expected, expected_sig_len)
    }
    Err(e) => fail("\{tag}: expected InvalidSignatureLength, got \{e}")
    Ok(_) => fail("\{tag}: expected InvalidSignatureLength, got Ok")
  }
  let overlong = @crypto.concat_bytes([sig_bytes, b"\x00"])
  match @moonfrost.deserialize_signature(ops, overlong) {
    Err(@frost.FrostError::InvalidSignatureLength(actual, expected)) => {
      assert_eq(actual, expected_sig_len + 1)
      assert_eq(expected, expected_sig_len)
    }
    Err(e) => fail("\{tag}: expected InvalidSignatureLength, got \{e}")
    Ok(_) => fail("\{tag}: expected InvalidSignatureLength, got Ok")
  }
}

///|
test "adversarial_25_signature_replay_bitflip_and_length_attacks" {
  check_signature_replay_bitflip_and_length(
    @moonfrost.ristretto255_sha512(),
    64,
    "adv25-r255",
  )
  check_signature_replay_bitflip_and_length(
    @moonfrost.p256_sha256(),
    65,
    "adv25-p256",
  )
}

///|
fn[S, E] check_set_mismatch_and_invalid_thresholds(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 2], "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps, [1, 2], nonces, comms, msg)

  // Participant set mismatch: commitment_list has [1, 2], sig_shares has [1, 3]
  let mismatched_shares : Array[@frost.SignatureShare[S]] = [
    shares[0],
    { identifier: 3, share: shares[1].share, },
  ]
  assert_true(
    @moonfrost.aggregate(ops, comms, msg, pub_pkg, mismatched_shares)
    is Err(@frost.FrostError::InvalidParticipantId(3)),
  )

  // Extra signature share beyond commitment_list length
  let extra_shares : Array[@frost.SignatureShare[S]] = [
    shares[0],
    shares[1],
    { identifier: 3, share: (ops.scalar_one)(), },
  ]
  assert_true(
    @moonfrost.aggregate(ops, comms, msg, pub_pkg, extra_shares)
    is Err(@frost.FrostError::InvalidParameters(_)),
  )

  // Invalid thresholds: min=0, min=1, min>max, max=0
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-thr"))
  let invalid_pairs : Array[(Int32, Int32)] = [
    (3, 0),
    (3, 1),
    (3, 4),
    (0, 0),
    (0, 2),
  ]
  for i = 0; i < invalid_pairs.length(); i = i + 1 {
    let (max_s, min_s) = invalid_pairs[i]
    assert_true(
      @moonfrost.trusted_dealer_keygen(ops, drbg, max_s, min_s)
      is Err(@frost.FrostError::InvalidThreshold(_)),
    )
    assert_true(
      @moonfrost.dkg_part1(ops, 1, max_s, min_s, drbg)
      is Err(@frost.FrostError::InvalidThreshold(_)),
    )
  }
}

///|
test "adversarial_26_participant_set_mismatch_and_invalid_thresholds" {
  check_set_mismatch_and_invalid_thresholds(
    @moonfrost.ristretto255_sha512(),
    "adv26-r255",
  )
  check_set_mismatch_and_invalid_thresholds(
    @moonfrost.p256_sha256(),
    "adv26-p256",
  )
}

///|
fn[S, E] check_dkg_part3_split_view_r1_substitution(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  // Red-team regression for CRITICAL #1:
  // Malicious peer 3 runs honest Round 1 & Round 2, then between dkg_part2 and
  // dkg_part3 substitutes its Round 1 package with a forged Rogue-Key commitment
  // C'_3 = [TargetPK - C_1,0 - C_2,0, -(1^-1)*C'_3,0] and sends zero share to P1.
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-dkg"))
  let r1_secrets : Array[@frost.DkgRound1Secret[S]] = []
  let r1_pkgs : Array[@frost.DkgRound1Package[S, E]] = []
  for id = 1; id <= 3; id = id + 1 {
    let (sec, pkg) = match @moonfrost.dkg_part1(ops, id, 3, 2, drbg) {
      Ok(v) => v
      Err(e) => fail("\{tag}: dkg_part1 failed: \{e}")
    }
    r1_secrets.push(sec)
    r1_pkgs.push(pkg)
  }
  let (p1_r2_sec, _) = match @moonfrost.dkg_part2(ops, r1_secrets[0], r1_pkgs) {
    Ok(v) => v
    Err(e) => fail("\{tag}: dkg_part2 P1 failed: \{e}")
  }
  // Also verify DkgRound1Secret cannot be reused after successful dkg_part2.
  assert_true(
    @moonfrost.dkg_part2(ops, r1_secrets[0], r1_pkgs)
    is Err(@frost.FrostError::InvalidParameters(_)),
  )
  let (_, p2_r2_pkgs) = match
    @moonfrost.dkg_part2(ops, r1_secrets[1], r1_pkgs) {
    Ok(v) => v
    Err(e) => fail("\{tag}: dkg_part2 P2 failed: \{e}")
  }
  let mut p2_to_p1_opt : @frost.DkgRound2Package[S]? = None
  for i = 0; i < p2_r2_pkgs.length(); i = i + 1 {
    if p2_r2_pkgs[i].receiver == 1 {
      p2_to_p1_opt = Some(p2_r2_pkgs[i])
      break
    }
  }
  let p2_to_p1 = match p2_to_p1_opt {
    Some(v) => v
    None => fail("\{tag}: missing P2->P1 share")
  }
  let target_pk = (ops.scalar_base_mul)((ops.scalar_from_u32)(777U))
  let c3_0 = (ops.element_sub)(
    (ops.element_sub)(target_pk, r1_pkgs[0].commitment.coeffs[0]),
    r1_pkgs[1].commitment.coeffs[0],
  )
  let c3_1 = (ops.element_neg)(c3_0)
  let forged_r1_p3 : @frost.DkgRound1Package[S, E] = {
    identifier: 3,
    commitment: { coeffs: [c3_0, c3_1], },
    pok_r: (ops.element_identity)(),
    pok_mu: (ops.scalar_zero)(),
  }
  let substituted_r1 : Array[@frost.DkgRound1Package[S, E]] = [
    r1_pkgs[0],
    r1_pkgs[1],
    forged_r1_p3,
  ]
  let forged_r2_for_p1 : Array[@frost.DkgRound2Package[S]] = [
    p2_to_p1,
    { sender: 3, receiver: 1, secret_share: (ops.scalar_zero)(), },
  ]
  assert_true(
    @moonfrost.dkg_part3(ops, p1_r2_sec, substituted_r1, forged_r2_for_p1)
    is Err(@frost.FrostError::InvalidVssCommitment(_)),
  )
}

///|
test "adversarial_27_dkg_part3_split_view_r1_substitution_rejected" {
  check_dkg_part3_split_view_r1_substitution(
    @moonfrost.ristretto255_sha512(),
    "adv27-r255",
  )
  check_dkg_part3_split_view_r1_substitution(
    @moonfrost.p256_sha256(),
    "adv27-p256",
  )
}

///|
fn[S, E] check_vss_downgrade_and_zero_share(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let secret = (ops.scalar_from_u32)(42U)
  // Leading coefficient = 0 would silently downgrade 2-of-3 into 1-of-3 -> must reject
  assert_true(
    @frost.secret_share_shard(ops, secret, [(ops.scalar_zero)()], 3)
    is Err(@frost.FrostError::InvalidThreshold(_)),
  )
  assert_true(
    @frost.trusted_dealer_keygen_with_secret(
      ops,
      secret,
      [(ops.scalar_zero)()],
      3,
    )
    is Err(@frost.FrostError::InvalidThreshold(_)),
  )
  // Zero secret in trusted_dealer_keygen_with_secret -> IdentityElement
  assert_true(
    @frost.trusted_dealer_keygen_with_secret(
      ops,
      (ops.scalar_zero)(),
      [(ops.scalar_one)()],
      3,
    )
    is Err(@frost.FrostError::IdentityElement),
  )
  // vss_verify with all-identity commitment & zero share -> must NOT return Ok(true)
  let id_elem = (ops.element_identity)()
  let id_comm : @frost.VssCommitment[E] = { coeffs: [id_elem, id_elem], }
  assert_true(
    @frost.vss_verify(ops, 1, (ops.scalar_zero)(), id_comm)
    is Err(@frost.FrostError::IdentityElement),
  )
  // vss_verify with non-identity C_0 and C_1 = -C_0 evaluates to identity at id=1 -> reject
  let g = (ops.element_generator)()
  let cancel_comm : @frost.VssCommitment[E] = {
    coeffs: [g, (ops.element_neg)(g)],
  }
  assert_true(
    @frost.vss_verify(ops, 1, (ops.scalar_zero)(), cancel_comm)
    is Err(@frost.FrostError::IdentityElement),
  )
  // derive_group_info rejects identity in higher-order coefficient C_1 and wrong length
  let higher_id_comm : @frost.VssCommitment[E] = { coeffs: [g, id_elem], }
  assert_true(
    @frost.derive_group_info(ops, 3, 2, higher_id_comm)
    is Err(@frost.FrostError::IdentityElement),
  )
  let wrong_len_comm : @frost.VssCommitment[E] = { coeffs: [g], }
  assert_true(
    @frost.derive_group_info(ops, 3, 2, wrong_len_comm)
    is Err(@frost.FrostError::InvalidVssCommitment(_)),
  )
  // max_signers > 65535 overflow guard
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-cap"))
  assert_true(
    @moonfrost.trusted_dealer_keygen(ops, drbg, 70000, 2)
    is Err(@frost.FrostError::InvalidThreshold(_)),
  )
}

///|
test "adversarial_28_vss_threshold_downgrade_and_zero_share_rejected" {
  check_vss_downgrade_and_zero_share(
    @moonfrost.ristretto255_sha512(),
    "adv28-r255",
  )
  check_vss_downgrade_and_zero_share(@moonfrost.p256_sha256(), "adv28-p256")
}

///|
fn[S, E] check_sign_out_of_range_peer_id(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, _, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let out_of_range_comms : Array[@frost.CommitmentEntry[E]] = [
    comms[0],
    @frost.CommitmentEntry::new(9999, comms[1].commitments),
  ]
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, out_of_range_comms)
    is Err(@frost.FrostError::InvalidParticipantId(9999)),
  )
  // Nonce must NOT have been consumed on rejected sign()
  assert_eq(nonces[0].is_used(), false)
}

///|
test "adversarial_29_sign_out_of_range_peer_id_rejected" {
  check_sign_out_of_range_peer_id(
    @moonfrost.ristretto255_sha512(),
    "adv29-r255",
  )
  check_sign_out_of_range_peer_id(@moonfrost.p256_sha256(), "adv29-p256")
}

///|
fn[S, E] check_aggregate_corrupted_pubkeys(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let shares = adv_round2_sign_subset(ops, kps, [1, 3], nonces, comms, msg)

  // Corrupt honest P1's verifying_share to identity -> must return IdentityElement,
  // NEVER falsely accuse honest P1 as CheaterDetected([1]).
  let bad_shares_list : Array[(Int32, E)] = [
    (1, (ops.element_identity)()),
    pub_pkg.verifying_shares[1],
    pub_pkg.verifying_shares[2],
  ]
  let bad_pub_identity : @frost.PublicKeyPackage[E] = {
    verifying_shares: bad_shares_list,
    verifying_key: pub_pkg.verifying_key,
    min_signers: pub_pkg.min_signers,
    max_signers: pub_pkg.max_signers,
  }
  assert_true(
    @moonfrost.aggregate(ops, comms, msg, bad_pub_identity, shares)
    is Err(@frost.FrostError::IdentityElement),
  )

  // Duplicate verifying_shares entry in pub_pkg -> DuplicateParticipant
  let dup_pub : @frost.PublicKeyPackage[E] = {
    verifying_shares: [
      pub_pkg.verifying_shares[0],
      pub_pkg.verifying_shares[0],
      pub_pkg.verifying_shares[2],
    ],
    verifying_key: pub_pkg.verifying_key,
    min_signers: pub_pkg.min_signers,
    max_signers: pub_pkg.max_signers,
  }
  assert_true(
    @moonfrost.aggregate(ops, comms, msg, dup_pub, shares)
    is Err(@frost.FrostError::DuplicateParticipant(1)),
  )
}

///|
test "adversarial_30_aggregate_corrupted_pubkeys_no_false_accusation" {
  check_aggregate_corrupted_pubkeys(
    @moonfrost.ristretto255_sha512(),
    "adv30-r255",
  )
  check_aggregate_corrupted_pubkeys(@moonfrost.p256_sha256(), "adv30-p256")
}

///|
fn[S, E] check_aggregate_wrong_msg_and_wrong_group_pk(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg_signed = @crypto.ascii_bytes("\{tag}-signed")
  let msg_wrong = @crypto.ascii_bytes("\{tag}-wrong")
  let (nonces, comms) = adv_round1_commit_subset(ops, kps, [1, 3], "\{tag}-r1")
  let shares = adv_round2_sign_subset(
    ops,
    kps,
    [1, 3],
    nonces,
    comms,
    msg_signed,
  )

  // Aggregating honest shares under wrong message -> both shares fail verification
  match @moonfrost.aggregate(ops, comms, msg_wrong, pub_pkg, shares) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [1, 3])
    Err(e) => fail("\{tag}: expected CheaterDetected([1, 3]), got \{e}")
    Ok(_) => fail("\{tag}: wrong message aggregate unexpectedly succeeded")
  }

  // Aggregating honest shares with mismatched group verifying_key (different PK)
  let wrong_pk_pkg : @frost.PublicKeyPackage[E] = {
    verifying_shares: pub_pkg.verifying_shares,
    verifying_key: (ops.element_add)(
      pub_pkg.verifying_key,
      (ops.element_generator)(),
    ),
    min_signers: pub_pkg.min_signers,
    max_signers: pub_pkg.max_signers,
  }
  match @moonfrost.aggregate(ops, comms, msg_signed, wrong_pk_pkg, shares) {
    Err(@frost.FrostError::CheaterDetected(ids)) => assert_eq(ids, [1, 3])
    Err(@frost.FrostError::InvalidSignature) => ()
    Err(e) =>
      fail("\{tag}: expected CheaterDetected or InvalidSignature, got \{e}")
    Ok(_) => fail("\{tag}: wrong group PK aggregate unexpectedly succeeded")
  }
}

///|
test "adversarial_31_aggregate_wrong_msg_and_wrong_group_pk" {
  check_aggregate_wrong_msg_and_wrong_group_pk(
    @moonfrost.ristretto255_sha512(),
    "adv31-r255",
  )
  check_aggregate_wrong_msg_and_wrong_group_pk(
    @moonfrost.p256_sha256(),
    "adv31-p256",
  )
}

///|
fn[S, E] check_dkg_malformed_packages_and_r1_dos(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-dkg"))
  // dkg_part1 out-of-range id > max_signers
  assert_true(
    @moonfrost.dkg_part1(ops, 4, 3, 2, drbg)
    is Err(@frost.FrostError::InvalidParticipantId(4)),
  )
  let r1_secrets : Array[@frost.DkgRound1Secret[S]] = []
  let r1_pkgs : Array[@frost.DkgRound1Package[S, E]] = []
  for id = 1; id <= 3; id = id + 1 {
    let (sec, pkg) = match @moonfrost.dkg_part1(ops, id, 3, 2, drbg) {
      Ok(v) => v
      Err(e) => fail("\{tag}: dkg_part1 failed: \{e}")
    }
    r1_secrets.push(sec)
    r1_pkgs.push(pkg)
  }

  // dkg_part2 identifiable abort on peer C_0 == identity, C_1 == identity, wrong coeffs length
  let bad_c0_pkgs : Array[@frost.DkgRound1Package[S, E]] = [
    r1_pkgs[0],
    {
      identifier: 2,
      commitment: {
        coeffs: [(ops.element_identity)(), r1_pkgs[1].commitment.coeffs[1]],
      },
      pok_r: r1_pkgs[1].pok_r,
      pok_mu: r1_pkgs[1].pok_mu,
    },
    r1_pkgs[2],
  ]
  match @moonfrost.dkg_part2(ops, r1_secrets[0], bad_c0_pkgs) {
    Err(@frost.FrostError::InvalidDkgProof(ids)) => assert_eq(ids, [2])
    Err(e) => fail("\{tag}: expected InvalidDkgProof([2]), got \{e}")
    Ok(_) => fail("\{tag}: expected InvalidDkgProof([2]), got Ok")
  }

  let bad_c1_and_len_pkgs : Array[@frost.DkgRound1Package[S, E]] = [
    r1_pkgs[0],
    {
      identifier: 2,
      commitment: {
        coeffs: [r1_pkgs[1].commitment.coeffs[0], (ops.element_identity)()],
      },
      pok_r: r1_pkgs[1].pok_r,
      pok_mu: r1_pkgs[1].pok_mu,
    },
    {
      identifier: 3,
      commitment: { coeffs: [r1_pkgs[2].commitment.coeffs[0]], },
      pok_r: r1_pkgs[2].pok_r,
      pok_mu: r1_pkgs[2].pok_mu,
    },
  ]
  match @moonfrost.dkg_part2(ops, r1_secrets[0], bad_c1_and_len_pkgs) {
    Err(@frost.FrostError::InvalidDkgProof(ids)) => assert_eq(ids, [2, 3])
    Err(e) => fail("\{tag}: expected InvalidDkgProof([2, 3]), got \{e}")
    Ok(_) => fail("\{tag}: expected InvalidDkgProof([2, 3]), got Ok")
  }

  // dkg_part2 structural errors: duplicate, insufficient, extra, out-of-range ID, own commitment mismatch
  assert_true(
    @moonfrost.dkg_part2(ops, r1_secrets[0], [
      r1_pkgs[0],
      r1_pkgs[1],
      r1_pkgs[1],
    ])
    is Err(@frost.FrostError::DuplicateParticipant(2)),
  )
  assert_true(
    @moonfrost.dkg_part2(ops, r1_secrets[0], [r1_pkgs[0], r1_pkgs[1]])
    is Err(@frost.FrostError::InsufficientParticipants(2, 3)),
  )
  assert_true(
    @moonfrost.dkg_part2(ops, r1_secrets[0], [
      r1_pkgs[0],
      r1_pkgs[1],
      r1_pkgs[2],
      r1_pkgs[2],
    ])
    is Err(@frost.FrostError::InvalidParameters(_)),
  )
  assert_true(
    @moonfrost.dkg_part2(ops, r1_secrets[0], [
      {
        identifier: 1,
        commitment: r1_pkgs[1].commitment,
        pok_r: r1_pkgs[0].pok_r,
        pok_mu: r1_pkgs[0].pok_mu,
      },
      r1_pkgs[1],
      r1_pkgs[2],
    ])
    is Err(@frost.FrostError::CommitmentMismatch(1)),
  )

  // Honest Round 2 -> test Round 3 structural rejections (wrong receiver, sender==own, duplicate, missing)
  let (p1_r2_sec, _) = match @moonfrost.dkg_part2(ops, r1_secrets[0], r1_pkgs) {
    Ok(v) => v
    Err(e) => fail("\{tag}: honest dkg_part2 failed: \{e}")
  }
  let (_, p2_r2_out) = match @moonfrost.dkg_part2(ops, r1_secrets[1], r1_pkgs) {
    Ok(v) => v
    Err(e) => fail("\{tag}: honest P2 dkg_part2 failed: \{e}")
  }
  let (_, p3_r2_out) = match @moonfrost.dkg_part2(ops, r1_secrets[2], r1_pkgs) {
    Ok(v) => v
    Err(e) => fail("\{tag}: honest P3 dkg_part2 failed: \{e}")
  }
  let p2_to_p1 = p2_r2_out[0]
  let p3_to_p1 = p3_r2_out[0]
  assert_true(
    @moonfrost.dkg_part3(ops, p1_r2_sec, r1_pkgs, [p2_to_p1])
    is Err(@frost.FrostError::InsufficientParticipants(1, 2)),
  )
  assert_true(
    @moonfrost.dkg_part3(ops, p1_r2_sec, r1_pkgs, [
      { sender: 2, receiver: 3, secret_share: p2_to_p1.secret_share, },
      p3_to_p1,
    ])
    is Err(@frost.FrostError::InvalidParticipantId(3)),
  )
  assert_true(
    @moonfrost.dkg_part3(ops, p1_r2_sec, r1_pkgs, [
      { sender: 1, receiver: 1, secret_share: p2_to_p1.secret_share, },
      p3_to_p1,
    ])
    is Err(@frost.FrostError::InvalidParticipantId(1)),
  )
  assert_true(
    @moonfrost.dkg_part3(ops, p1_r2_sec, r1_pkgs, [p2_to_p1, p2_to_p1])
    is Err(@frost.FrostError::DuplicateParticipant(2)),
  )
}

///|
test "adversarial_32_dkg_malformed_packages_and_identifiable_r1_dos" {
  check_dkg_malformed_packages_and_r1_dos(
    @moonfrost.ristretto255_sha512(),
    "adv32-r255",
  )
  check_dkg_malformed_packages_and_r1_dos(
    @moonfrost.p256_sha256(),
    "adv32-p256",
  )
}

///|
test "adversarial_33_deserialize_signature_and_serialize_edge_cases" {
  // Ristretto255
  let r255 = @moonfrost.ristretto255_sha512()
  let bad_r_r255 : @frost.Signature[
    @ristretto255.Scalar,
    @ristretto255.RistrettoPoint,
  ] = { r: (r255.element_identity)(), z: (r255.scalar_one)(), }
  assert_true(
    @moonfrost.serialize_signature(r255, bad_r_r255)
    is Err(@frost.FrostError::IdentityElement),
  )
  // 32 zero bytes (identity R) + valid z -> InvalidElement
  let zero_r_r255 = @crypto.concat_bytes([
    Bytes::make(32, b'\x00'),
    (r255.serialize_scalar)((r255.scalar_one)()),
  ])
  assert_true(
    @moonfrost.deserialize_signature(r255, zero_r_r255)
    is Err(@frost.FrostError::InvalidElement(_)),
  )
  // Valid R + non-canonical z (0xff * 32) -> InvalidScalar
  let valid_r_r255 = match
    (r255.serialize_element)((r255.element_generator)()) {
    Ok(b) => b
    Err(e) => fail("serialize_element failed: \{e}")
  }
  let bad_z_r255 = @crypto.concat_bytes([valid_r_r255, Bytes::make(32, b'\xff')])
  assert_true(
    @moonfrost.deserialize_signature(r255, bad_z_r255)
    is Err(@frost.FrostError::InvalidScalar(_)),
  )

  // P-256
  let p256 = @moonfrost.p256_sha256()
  let bad_r_p256 : @frost.Signature[@p256.Scalar, @p256.P256Point] = {
    r: (p256.element_identity)(),
    z: (p256.scalar_one)(),
  }
  assert_true(
    @moonfrost.serialize_signature(p256, bad_r_p256)
    is Err(@frost.FrostError::IdentityElement),
  )
  let zero_r_p256 = @crypto.concat_bytes([
    Bytes::make(33, b'\x00'),
    (p256.serialize_scalar)((p256.scalar_one)()),
  ])
  assert_true(
    @moonfrost.deserialize_signature(p256, zero_r_p256)
    is Err(@frost.FrostError::InvalidElement(_)),
  )
  let valid_r_p256 = match
    (p256.serialize_element)((p256.element_generator)()) {
    Ok(b) => b
    Err(e) => fail("serialize_element failed: \{e}")
  }
  let bad_z_p256 = @crypto.concat_bytes([valid_r_p256, Bytes::make(32, b'\xff')])
  assert_true(
    @moonfrost.deserialize_signature(p256, bad_z_p256)
    is Err(@frost.FrostError::InvalidScalar(_)),
  )
}

///|
fn[S, E] check_sign_overflow_and_prime_order_edges(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> Unit raise {
  let (kps, pub_pkg, _) = adv_setup_dealer(ops, 3, 2, "\{tag}-dealer")
  let msg = @crypto.ascii_bytes("\{tag}-msg")
  let (nonces, comms) = adv_round1_commit_subset(
    ops,
    kps,
    [1, 2, 3],
    "\{tag}-r1",
  )

  // Signer not present in commitment_list -> InvalidParticipantId
  let without_p1 : Array[@frost.CommitmentEntry[E]] = [comms[1], comms[2]]
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, without_p1)
    is Err(@frost.FrostError::InvalidParticipantId(1)),
  )
  assert_eq(nonces[0].is_used(), false)

  // commitment_list.length() > max_signers -> InvalidParameters
  let too_many : Array[@frost.CommitmentEntry[E]] = [
    comms[0],
    comms[1],
    comms[2],
    @frost.CommitmentEntry::new(4, comms[2].commitments),
  ]
  assert_true(
    @moonfrost.sign(ops, kps[0], nonces[0], msg, too_many)
    is Err(@frost.FrostError::InvalidParameters(_)),
  )

  // nonce_generate_with_randomness rejects non-32-byte randomness
  assert_true(
    @frost.nonce_generate_with_randomness(
      ops,
      kps[0].signing_share,
      Bytes::make(31, b'\x42'),
    )
    is Err(@frost.FrostError::InvalidParameters(_)),
  )

  // prime_order_sign rejects zero secret key, succeeds on valid key and verifies
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-po"))
  assert_true(
    @moonfrost.prime_order_sign(ops, msg, (ops.scalar_zero)(), drbg)
    is Err(@frost.FrostError::IdentityElement),
  )
  let sk = @frost.random_nonzero_scalar(ops, drbg)
  let pk = (ops.scalar_base_mul)(sk)
  let po_sig = match @moonfrost.prime_order_sign(ops, msg, sk, drbg) {
    Ok(s) => s
    Err(e) => fail("\{tag}: prime_order_sign failed: \{e}")
  }
  assert_eq(@moonfrost.prime_order_verify(ops, msg, po_sig, pk), Ok(true))

  // verify_signature_share error paths: invalid ID, identity verifying_share, commitment mismatch
  let bad_share = (ops.scalar_one)()
  assert_true(
    @moonfrost.verify_signature_share(
      ops,
      0,
      kps[0].verifying_share,
      comms[0].commitments,
      bad_share,
      comms,
      pub_pkg.verifying_key,
      msg,
    )
    is Err(@frost.FrostError::InvalidParticipantId(0)),
  )
  assert_true(
    @moonfrost.verify_signature_share(
      ops,
      1,
      (ops.element_identity)(),
      comms[0].commitments,
      bad_share,
      comms,
      pub_pkg.verifying_key,
      msg,
    )
    is Err(@frost.FrostError::IdentityElement),
  )
  assert_true(
    @moonfrost.verify_signature_share(
      ops,
      1,
      kps[0].verifying_share,
      comms[1].commitments,
      bad_share,
      comms,
      pub_pkg.verifying_key,
      msg,
    )
    is Err(@frost.FrostError::CommitmentMismatch(1)),
  )
}

///|
test "adversarial_34_sign_overflow_list_and_prime_order_sign_zero_key" {
  check_sign_overflow_and_prime_order_edges(
    @moonfrost.ristretto255_sha512(),
    "adv34-r255",
  )
  check_sign_overflow_and_prime_order_edges(
    @moonfrost.p256_sha256(),
    "adv34-p256",
  )
}

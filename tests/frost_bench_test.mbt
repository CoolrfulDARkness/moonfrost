///|
/// Performance benchmarks (`moon bench`) for both RFC 9591 ciphersuites:
/// - FROST(ristretto255, SHA-512)
/// - FROST(P-256, SHA-256)
///
/// Note on `bench_*_sign`: because `SigningNonces` strictly enforces one-time
/// consumption (`NonceAlreadyUsed` on reuse), each benchmark iteration mints a
/// fresh commitment/nonce pair and produces a Round 2 signature share against
/// a 3-of-5 commitment list. `bench_*_commit` isolates Round 1 alone.

///|
fn[S, E] bench_run_dkg_3of5(
  ops : @frost.SuiteOps[S, E],
  seed : Bytes,
) -> (Array[@frost.KeyPackage[S, E]], @frost.PublicKeyPackage[E]) {
  let drbg = @moonfrost.drbg_from_seed(seed)
  let r1_secrets : Array[@frost.DkgRound1Secret[S]] = []
  let r1_pkgs : Array[@frost.DkgRound1Package[S, E]] = []
  for id = 1; id <= 5; id = id + 1 {
    let (sec, pkg) = match @moonfrost.dkg_part1(ops, id, 5, 3, drbg) {
      Ok(v) => v
      Err(e) => abort("bench dkg_part1 failed: \{e}")
    }
    r1_secrets.push(sec)
    r1_pkgs.push(pkg)
  }
  let r2_secrets : Array[@frost.DkgRound2Secret[S, E]] = []
  let inboxes : Array[Array[@frost.DkgRound2Package[S]]] = [[], [], [], [], []]
  for i = 0; i < 5; i = i + 1 {
    let (sec, out_pkgs) = match
      @moonfrost.dkg_part2(ops, r1_secrets[i], r1_pkgs) {
      Ok(v) => v
      Err(e) => abort("bench dkg_part2 failed: \{e}")
    }
    r2_secrets.push(sec)
    for j = 0; j < out_pkgs.length(); j = j + 1 {
      let pkg = out_pkgs[j]
      inboxes[pkg.receiver - 1].push(pkg)
    }
  }
  let kps : Array[@frost.KeyPackage[S, E]] = []
  let mut pub_opt : @frost.PublicKeyPackage[E]? = None
  for i = 0; i < 5; i = i + 1 {
    let (kp, pub_pkg) = match
      @moonfrost.dkg_part3(ops, r2_secrets[i], r1_pkgs, inboxes[i]) {
      Ok(v) => v
      Err(e) => abort("bench dkg_part3 failed: \{e}")
    }
    kps.push(kp)
    pub_opt = Some(pub_pkg)
  }
  match pub_opt {
    Some(p) => (kps, p)
    None => abort("unreachable")
  }
}

///|
fn[S, E] bench_prepare_3of5(
  ops : @frost.SuiteOps[S, E],
  tag : String,
) -> (
  Array[@frost.KeyPackage[S, E]],
  @frost.PublicKeyPackage[E],
  Array[@frost.CommitmentEntry[E]],
  Array[@frost.SignatureShare[S]],
  @frost.Signature[S, E],
  Bytes,
) {
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("\{tag}-setup"))
  let (kps, pub_pkg, _) = match
    @moonfrost.trusted_dealer_keygen(ops, drbg, 5, 3) {
    Ok(v) => v
    Err(e) => abort("bench keygen failed: \{e}")
  }
  let msg = @crypto.ascii_bytes("moonfrost-rfc9591-benchmark-payload")
  let signer_ids : Array[Int32] = [1, 3, 5]
  let nonces : Array[@frost.SigningNonces[S, E]] = []
  let comms : Array[@frost.CommitmentEntry[E]] = []
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let kp = kps[signer_ids[i] - 1]
    let (n, c) = match @moonfrost.commit(ops, kp.signing_share, drbg) {
      Ok(v) => v
      Err(e) => abort("bench commit failed: \{e}")
    }
    nonces.push(n)
    comms.push(@frost.CommitmentEntry::new(kp.identifier, c))
  }
  let shares : Array[@frost.SignatureShare[S]] = []
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let kp = kps[signer_ids[i] - 1]
    let s = match @moonfrost.sign(ops, kp, nonces[i], msg, comms) {
      Ok(v) => v
      Err(e) => abort("bench sign failed: \{e}")
    }
    shares.push(s)
  }
  let sig = match @moonfrost.aggregate(ops, comms, msg, pub_pkg, shares) {
    Ok(v) => v
    Err(e) => abort("bench aggregate failed: \{e}")
  }
  (kps, pub_pkg, comms, shares, sig, msg)
}

///|
test "bench_ristretto255_dkg_3of5" (b : @bench.T) {
  let ops = @moonfrost.ristretto255_sha512()
  let seed = @crypto.ascii_bytes("bench-r255-dkg-3of5")
  b.bench(fn() { b.keep(bench_run_dkg_3of5(ops, seed)) })
}

///|
test "bench_ristretto255_commit" (b : @bench.T) {
  let ops = @moonfrost.ristretto255_sha512()
  let (kps, _, _, _, _, _) = bench_prepare_3of5(ops, "r255-commit")
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("bench-r255-commit"))
  let share = kps[0].signing_share
  b.bench(fn() { b.keep(@moonfrost.commit(ops, share, drbg)) })
}

///|
test "bench_ristretto255_sign" (b : @bench.T) {
  let ops = @moonfrost.ristretto255_sha512()
  let (kps, _, base_comms, _, _, msg) = bench_prepare_3of5(ops, "r255-sign")
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("bench-r255-sign"))
  let kp1 = kps[0]
  b.bench(fn() {
    let (nonces, comms) = match
      @moonfrost.commit(ops, kp1.signing_share, drbg) {
      Ok(v) => v
      Err(e) => abort("bench sign commit failed: \{e}")
    }
    let comm_list : Array[@frost.CommitmentEntry[@ristretto255.RistrettoPoint]] = [
      @frost.CommitmentEntry::new(1, comms),
      base_comms[1],
      base_comms[2],
    ]
    b.keep(@moonfrost.sign(ops, kp1, nonces, msg, comm_list))
  })
}

///|
test "bench_ristretto255_aggregate_3of5" (b : @bench.T) {
  let ops = @moonfrost.ristretto255_sha512()
  let (_, pub_pkg, comms, shares, _, msg) = bench_prepare_3of5(ops, "r255-agg")
  b.bench(fn() {
    b.keep(@moonfrost.aggregate(ops, comms, msg, pub_pkg, shares))
  })
}

///|
test "bench_ristretto255_verify" (b : @bench.T) {
  let ops = @moonfrost.ristretto255_sha512()
  let (_, pub_pkg, _, _, sig, msg) = bench_prepare_3of5(ops, "r255-ver")
  let pk = pub_pkg.verifying_key
  b.bench(fn() { b.keep(@moonfrost.prime_order_verify(ops, msg, sig, pk)) })
}

///|
test "bench_p256_dkg_3of5" (b : @bench.T) {
  let ops = @moonfrost.p256_sha256()
  let seed = @crypto.ascii_bytes("bench-p256-dkg-3of5")
  b.bench(fn() { b.keep(bench_run_dkg_3of5(ops, seed)) })
}

///|
test "bench_p256_commit" (b : @bench.T) {
  let ops = @moonfrost.p256_sha256()
  let (kps, _, _, _, _, _) = bench_prepare_3of5(ops, "p256-commit")
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("bench-p256-commit"))
  let share = kps[0].signing_share
  b.bench(fn() { b.keep(@moonfrost.commit(ops, share, drbg)) })
}

///|
test "bench_p256_sign" (b : @bench.T) {
  let ops = @moonfrost.p256_sha256()
  let (kps, _, base_comms, _, _, msg) = bench_prepare_3of5(ops, "p256-sign")
  let drbg = @moonfrost.drbg_from_seed(@crypto.ascii_bytes("bench-p256-sign"))
  let kp1 = kps[0]
  b.bench(fn() {
    let (nonces, comms) = match
      @moonfrost.commit(ops, kp1.signing_share, drbg) {
      Ok(v) => v
      Err(e) => abort("bench sign commit failed: \{e}")
    }
    let comm_list : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
      @frost.CommitmentEntry::new(1, comms),
      base_comms[1],
      base_comms[2],
    ]
    b.keep(@moonfrost.sign(ops, kp1, nonces, msg, comm_list))
  })
}

///|
test "bench_p256_aggregate_3of5" (b : @bench.T) {
  let ops = @moonfrost.p256_sha256()
  let (_, pub_pkg, comms, shares, _, msg) = bench_prepare_3of5(ops, "p256-agg")
  b.bench(fn() {
    b.keep(@moonfrost.aggregate(ops, comms, msg, pub_pkg, shares))
  })
}

///|
test "bench_p256_verify" (b : @bench.T) {
  let ops = @moonfrost.p256_sha256()
  let (_, pub_pkg, _, _, sig, msg) = bench_prepare_3of5(ops, "p256-ver")
  let pk = pub_pkg.verifying_key
  b.bench(fn() { b.keep(@moonfrost.prime_order_verify(ops, msg, sig, pk)) })
}

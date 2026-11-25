///|
fn must_hex(hex : String) -> Bytes {
  match @crypto.hex_to_bytes(hex) {
    Ok(b) => b
    Err(e) => abort(e)
  }
}

///|
fn[S, E] must_scalar_from_hex(ops : @frost.SuiteOps[S, E], hex : String) -> S {
  match (ops.deserialize_scalar)(must_hex(hex)) {
    Ok(s) => s
    Err(e) => abort(e)
  }
}

///|
fn[S, E] run_threshold_signing(
  ops : @frost.SuiteOps[S, E],
  key_packages : Array[@frost.KeyPackage[S, E]],
  pub_pkg : @frost.PublicKeyPackage[E],
  signer_indices : Array[Int32],
  msg : Bytes,
  drbg : @crypto.Drbg,
) -> Result[@frost.Signature[S, E], @frost.FrostError] {
  let nonces_list : Array[@frost.SigningNonces[S, E]] = []
  let comm_list : Array[@frost.CommitmentEntry[E]] = []
  for i = 0; i < signer_indices.length(); i = i + 1 {
    let kp = key_packages[signer_indices[i]]
    let (nonces, comms) = match @frost.commit(ops, kp.signing_share, drbg) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    nonces_list.push(nonces)
    comm_list.push({ identifier: kp.identifier, commitments: comms, })
  }
  let sig_shares : Array[@frost.SignatureShare[S]] = []
  for i = 0; i < signer_indices.length(); i = i + 1 {
    let kp = key_packages[signer_indices[i]]
    let share = match @frost.sign(ops, kp, nonces_list[i], msg, comm_list) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    sig_shares.push(share)
  }
  @frost.aggregate(ops, comm_list, msg, pub_pkg, sig_shares)
}

///|
fn[S, E] run_dkg_protocol(
  ops : @frost.SuiteOps[S, E],
  max_signers : Int32,
  min_signers : Int32,
  seed_prefix : String,
) -> Result[
  (Array[@frost.KeyPackage[S, E]], @frost.PublicKeyPackage[E]),
  @frost.FrostError,
] {
  let r1_secrets : Array[@frost.DkgRound1Secret[S]] = []
  let r1_packages : Array[@frost.DkgRound1Package[S, E]] = []
  for id = 1; id <= max_signers; id = id + 1 {
    let drbg = @crypto.Drbg::from_seed(
      @crypto.ascii_bytes("\{seed_prefix}-p\{id}"),
    )
    let (sec, pkg) = match
      @frost.dkg_part1(ops, id, max_signers, min_signers, drbg) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    r1_secrets.push(sec)
    r1_packages.push(pkg)
  }
  let r2_secrets : Array[@frost.DkgRound2Secret[S, E]] = []
  let r2_inboxes : Array[Array[@frost.DkgRound2Package[S]]] = []
  for _i = 0; _i < max_signers; _i = _i + 1 {
    r2_inboxes.push([])
  }
  for i = 0; i < max_signers; i = i + 1 {
    let (r2_sec, out_pkgs) = match
      @frost.dkg_part2(ops, r1_secrets[i], r1_packages) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    r2_secrets.push(r2_sec)
    for j = 0; j < out_pkgs.length(); j = j + 1 {
      let pkg = out_pkgs[j]
      r2_inboxes[pkg.receiver - 1].push(pkg)
    }
  }
  let key_packages : Array[@frost.KeyPackage[S, E]] = []
  let mut shared_pub : @frost.PublicKeyPackage[E]? = None
  for i = 0; i < max_signers; i = i + 1 {
    let (kp, pub_pkg) = match
      @frost.dkg_part3(ops, r2_secrets[i], r1_packages, r2_inboxes[i]) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    key_packages.push(kp)
    match shared_pub {
      None => shared_pub = Some(pub_pkg)
      Some(prev) =>
        if !(ops.element_eq)(prev.verifying_key, pub_pkg.verifying_key) {
          return Err(
            @frost.FrostError::InvalidVssCommitment(
              "DKG verifying_key mismatch across participants",
            ),
          )
        }
    }
  }
  match shared_pub {
    Some(p) => Ok((key_packages, p))
    None => Err(@frost.FrostError::InvalidParameters("empty DKG"))
  }
}

///|
test "RFC 9591 Appendix E.3: FROST(ristretto255, SHA-512) byte-for-byte vector" {
  let ops = @frost.ristretto255_sha512()
  let secret = must_scalar_from_hex(
    ops, "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
  )
  let coeff1 = must_scalar_from_hex(
    ops, "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02",
  )
  let msg = must_hex("74657374")

  let (kps, pub_pkg, commitment) = match
    @frost.trusted_dealer_keygen_with_secret(ops, secret, [coeff1], 3) {
    Ok(v) => v
    Err(e) => fail("keygen failed: \{e}")
  }
  // Group public key
  let gpk_hex = match (ops.serialize_element)(pub_pkg.verifying_key) {
    Ok(b) => @crypto.bytes_to_hex(b)
    Err(e) => fail(e)
  }
  assert_eq(
    gpk_hex, "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
  )
  // Participant shares P1, P2, P3
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(kps[0].signing_share)),
    "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(kps[1].signing_share)),
    "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(kps[2].signing_share)),
    "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
  )
  for i = 0; i < 3; i = i + 1 {
    assert_eq(
      @frost.vss_verify(
        ops,
        kps[i].identifier,
        kps[i].signing_share,
        commitment,
      ),
      Ok(true),
    )
  }
  // Secret reconstruction check
  let recovered = match
    @frost.secret_share_combine(
      ops,
      [(1, kps[0].signing_share), (3, kps[2].signing_share)],
      2,
    ) {
    Ok(s) => s
    Err(e) => fail("combine failed: \{e}")
  }
  assert_true((ops.scalar_eq)(recovered, secret))

  // Round 1: P1 and P3 with RFC Appendix E.3 randomness
  let p1_h_rand = must_hex(
    "f595a133b4d95c6e1f79887220c8b275ce6277e7f68a6640e1e7140f9be2fb5c",
  )
  let p1_b_rand = must_hex(
    "34dd1001360e3513cb37bebfabe7be4a32c5bb91ba19fbd4360d039111f0fbdc",
  )
  let p3_h_rand = must_hex(
    "daa0cf42a32617786d390e0c7edfbf2efbd428037069357b5173ae61d6dd5d5e",
  )
  let p3_b_rand = must_hex(
    "b4387e72b2e4108ce4168931cc2c7fcce5f345a5297368952c18b5fc8473f050",
  )

  let p1_hn = match
    @frost.nonce_generate_with_randomness(ops, kps[0].signing_share, p1_h_rand) {
    Ok(s) => s
    Err(e) => fail("\{e}")
  }
  let p1_bn = match
    @frost.nonce_generate_with_randomness(ops, kps[0].signing_share, p1_b_rand) {
    Ok(s) => s
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(p1_hn)),
    "214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(p1_bn)),
    "c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c",
  )

  let (p1_nonces, p1_comm) = match
    @frost.commit_with_randomness(
      ops,
      kps[0].signing_share,
      p1_h_rand,
      p1_b_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let (p3_nonces, p3_comm) = match
    @frost.commit_with_randomness(
      ops,
      kps[2].signing_share,
      p3_h_rand,
      p3_b_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p1_comm.hiding).unwrap()),
    "965def4d0958398391fc06d8c2d72932608b1e6255226de4fb8d972dac15fd57",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p1_comm.binding).unwrap()),
    "ec5170920660820007ae9e1d363936659ef622f99879898db86e5bf1d5bf2a14",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p3_comm.hiding).unwrap()),
    "480e06e3de182bf83489c45d7441879932fd7b434a26af41455756264fbd5d6e",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p3_comm.binding).unwrap()),
    "3064746dfd3c1862ef58fc68c706da287dd925066865ceacc816b3a28c7b363b",
  )

  let comm_list : Array[@frost.CommitmentEntry[@ristretto255.RistrettoPoint]] = [
    { identifier: 1, commitments: p1_comm, },
    { identifier: 3, commitments: p3_comm, },
  ]
  let bf_inputs = match
    @frost.compute_binding_factor_inputs(
      ops,
      pub_pkg.verifying_key,
      comm_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex(bf_inputs[0].1),
    "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f572889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b033911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d4603e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(
    @crypto.bytes_to_hex(bf_inputs[1].1),
    "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f572889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b033911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d4603e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f0300000000000000000000000000000000000000000000000000000000000000",
  )
  let bfs = match
    @frost.compute_binding_factors(ops, pub_pkg.verifying_key, comm_list, msg) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(bfs[0].1)),
    "8967fd70fa06a58e5912603317fa94c77626395a695a0e4e4efc4476662eba0c",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(bfs[1].1)),
    "f2c1bb7c33a10511158c2f1766a4a5fadf9f86f2a92692ed333128277cc31006",
  )

  // Round 2: Signature shares
  let s1 = match @frost.sign(ops, kps[0], p1_nonces, msg, comm_list) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let s3 = match @frost.sign(ops, kps[2], p3_nonces, msg, comm_list) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_true(p1_nonces.is_used())
  assert_true(p3_nonces.is_used())
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(s1.share)),
    "9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(s3.share)),
    "7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908",
  )

  // Aggregate + serialize + verify
  let sig = match @frost.aggregate(ops, comm_list, msg, pub_pkg, [s1, s3]) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let sig_bytes = match @frost.serialize_signature(ops, sig) {
    Ok(b) => b
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex(sig_bytes),
    "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb25552164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802",
  )
  let decoded = match @frost.deserialize_signature(ops, sig_bytes) {
    Ok(s) => s
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @frost.prime_order_verify(ops, msg, decoded, pub_pkg.verifying_key),
    Ok(true),
  )
}

///|
test "RFC 9591 Appendix E.4: FROST(P-256, SHA-256) byte-for-byte vector" {
  let ops = @frost.p256_sha256()
  let secret = must_scalar_from_hex(
    ops, "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
  )
  let coeff1 = must_scalar_from_hex(
    ops, "80f25e6c0709353e46bfbe882a11bdbb1f8097e46340eb8673b7e14556e6c3a4",
  )
  let msg = must_hex("74657374")

  let (kps, pub_pkg, commitment) = match
    @frost.trusted_dealer_keygen_with_secret(ops, secret, [coeff1], 3) {
    Ok(v) => v
    Err(e) => fail("keygen failed: \{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex(
      (ops.serialize_element)(pub_pkg.verifying_key).unwrap(),
    ),
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(kps[0].signing_share)),
    "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(kps[1].signing_share)),
    "8d8e787bef0ff6c2f494ca45f4dad198c6bee01212d6c84067159c52e1863ad5",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(kps[2].signing_share)),
    "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928",
  )
  for i = 0; i < 3; i = i + 1 {
    assert_eq(
      @frost.vss_verify(
        ops,
        kps[i].identifier,
        kps[i].signing_share,
        commitment,
      ),
      Ok(true),
    )
  }

  let p1_h_rand = must_hex(
    "ec4c891c85fee802a9d757a67d1252e7f4e5efb8a538991ac18fbd0e06fb6fd3",
  )
  let p1_b_rand = must_hex(
    "9334e29d09061223f69a09421715a347e4e6deba77444c8f42b0c833f80f4ef9",
  )
  let p3_h_rand = must_hex(
    "c0451c5a0a5480d6c1f860e5db7d655233dca2669fd90ff048454b8ce983367b",
  )
  let p3_b_rand = must_hex(
    "2ba5f7793ae700e40e78937a82f407dd35e847e33d1e607b5c7eb6ed2a8ed799",
  )

  let (p1_nonces, p1_comm) = match
    @frost.commit_with_randomness(
      ops,
      kps[0].signing_share,
      p1_h_rand,
      p1_b_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let (p3_nonces, p3_comm) = match
    @frost.commit_with_randomness(
      ops,
      kps[2].signing_share,
      p3_h_rand,
      p3_b_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p1_comm.hiding).unwrap()),
    "0213b3e6298bf8ad46fd5e9389519a8665d63d98f4ec6a1fcca434e809d2d8070e",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p1_comm.binding).unwrap()),
    "02188ff1390bf69374d7b272e454b1878ef10a6b6ea3ff36f114b300b4dbd5233b",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p3_comm.hiding).unwrap()),
    "033ac9a5fe4a8b57316ba1c34e8a6de453033b750e8984924a984eb67a11e73a3f",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_element)(p3_comm.binding).unwrap()),
    "03a7a2480ee16199262e648aea3acab628a53e9b8c1945078f2ddfbdc98b7df369",
  )

  let comm_list : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    { identifier: 1, commitments: p1_comm, },
    { identifier: 3, commitments: p3_comm, },
  ]
  let bf_inputs = match
    @frost.compute_binding_factor_inputs(
      ops,
      pub_pkg.verifying_key,
      comm_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex(bf_inputs[0].1),
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd0000000000000000000000000000000000000000000000000000000000000001",
  )
  assert_eq(
    @crypto.bytes_to_hex(bf_inputs[1].1),
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd0000000000000000000000000000000000000000000000000000000000000003",
  )
  let bfs = match
    @frost.compute_binding_factors(ops, pub_pkg.verifying_key, comm_list, msg) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(bfs[0].1)),
    "7925f0d4693f204e6e59233e92227c7124664a99739d2c06b81cf64ddf90559e",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(bfs[1].1)),
    "e10d24a8a403723bcb6f9bb4c537f316593683b472f7a89f166630dde11822c4",
  )

  let s1 = match @frost.sign(ops, kps[0], p1_nonces, msg, comm_list) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let s3 = match @frost.sign(ops, kps[2], p3_nonces, msg, comm_list) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(s1.share)),
    "400308eaed7a2ddee02a265abe6a1cfe04d946ee8720768899619cfabe7a3aeb",
  )
  assert_eq(
    @crypto.bytes_to_hex((ops.serialize_scalar)(s3.share)),
    "561da3c179edbb0502d941bb3e3ace3c37d122aaa46fb54499f15f3a3331de44",
  )

  let sig = match @frost.aggregate(ops, comm_list, msg, pub_pkg, [s1, s3]) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let sig_bytes = match @frost.serialize_signature(ops, sig) {
    Ok(b) => b
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @crypto.bytes_to_hex(sig_bytes),
    "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d9620acac6767e8e3e3036815fca4eb3a3caa69992b902bcd3352fc34f1ac192f",
  )
  let decoded = match @frost.deserialize_signature(ops, sig_bytes) {
    Ok(s) => s
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @frost.prime_order_verify(ops, msg, decoded, pub_pkg.verifying_key),
    Ok(true),
  )
}

///|
test "Trusted Dealer 2-of-3 and 3-of-5 signing across both suites" {
  let msg = @crypto.ascii_bytes("moonfrost threshold signing message")
  let wrong_msg = @crypto.ascii_bytes("tampered message")

  // Ristretto255 2-of-3 and 3-of-5
  let r_ops = @frost.ristretto255_sha512()
  let r_drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("td-ristretto"))
  let (r_kps3, r_pub3, _) = match
    @frost.trusted_dealer_keygen(r_ops, r_drbg, 3, 2) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let r_sig23 = match
    run_threshold_signing(r_ops, r_kps3, r_pub3, [1, 2], msg, r_drbg) {
    Ok(s) => s
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @frost.prime_order_verify(r_ops, msg, r_sig23, r_pub3.verifying_key),
    Ok(true),
  )
  assert_eq(
    @frost.prime_order_verify(r_ops, wrong_msg, r_sig23, r_pub3.verifying_key),
    Ok(false),
  )

  let (r_kps5, r_pub5, _) = match
    @frost.trusted_dealer_keygen(r_ops, r_drbg, 5, 3) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let subsets : Array[Array[Int32]] = [
    [0, 1, 2],
    [0, 2, 4],
    [1, 3, 4],
    [0, 1, 2, 3],
  ]
  for i = 0; i < subsets.length(); i = i + 1 {
    let sig = match
      run_threshold_signing(r_ops, r_kps5, r_pub5, subsets[i], msg, r_drbg) {
      Ok(s) => s
      Err(e) => fail("\{e}")
    }
    assert_eq(
      @frost.prime_order_verify(r_ops, msg, sig, r_pub5.verifying_key),
      Ok(true),
    )
  }

  // P-256 2-of-3 and 3-of-5
  let p_ops = @frost.p256_sha256()
  let p_drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("td-p256"))
  let (p_kps3, p_pub3, _) = match
    @frost.trusted_dealer_keygen(p_ops, p_drbg, 3, 2) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let p_sig23 = match
    run_threshold_signing(p_ops, p_kps3, p_pub3, [0, 2], msg, p_drbg) {
    Ok(s) => s
    Err(e) => fail("\{e}")
  }
  assert_eq(
    @frost.prime_order_verify(p_ops, msg, p_sig23, p_pub3.verifying_key),
    Ok(true),
  )
  assert_eq(
    @frost.prime_order_verify(p_ops, wrong_msg, p_sig23, p_pub3.verifying_key),
    Ok(false),
  )

  let (p_kps5, p_pub5, _) = match
    @frost.trusted_dealer_keygen(p_ops, p_drbg, 5, 3) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  for i = 0; i < subsets.length(); i = i + 1 {
    let sig = match
      run_threshold_signing(p_ops, p_kps5, p_pub5, subsets[i], msg, p_drbg) {
      Ok(s) => s
      Err(e) => fail("\{e}")
    }
    assert_eq(
      @frost.prime_order_verify(p_ops, msg, sig, p_pub5.verifying_key),
      Ok(true),
    )
  }
}

///|
test "Pedersen DKG 3-of-5 end-to-end and arbitrary subset signing (both suites)" {
  let msg = @crypto.ascii_bytes("pedersen dkg threshold signature")

  // Ristretto255 DKG 3-of-5
  let r_ops = @frost.ristretto255_sha512()
  let (r_kps, r_pub) = match run_dkg_protocol(r_ops, 5, 3, "dkg-r255") {
    Ok(v) => v
    Err(e) => fail("ristretto255 DKG failed: \{e}")
  }
  let r_drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("dkg-r255-sign"))
  let r_subsets : Array[Array[Int32]] = [[0, 1, 2], [0, 2, 4], [2, 3, 4]]
  for i = 0; i < r_subsets.length(); i = i + 1 {
    let sig = match
      run_threshold_signing(r_ops, r_kps, r_pub, r_subsets[i], msg, r_drbg) {
      Ok(s) => s
      Err(e) => fail("DKG sign failed: \{e}")
    }
    assert_eq(
      @frost.prime_order_verify(r_ops, msg, sig, r_pub.verifying_key),
      Ok(true),
    )
  }

  // P-256 DKG 3-of-5
  let p_ops = @frost.p256_sha256()
  let (p_kps, p_pub) = match run_dkg_protocol(p_ops, 5, 3, "dkg-p256") {
    Ok(v) => v
    Err(e) => fail("p256 DKG failed: \{e}")
  }
  let p_drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("dkg-p256-sign"))
  for i = 0; i < r_subsets.length(); i = i + 1 {
    let sig = match
      run_threshold_signing(p_ops, p_kps, p_pub, r_subsets[i], msg, p_drbg) {
      Ok(s) => s
      Err(e) => fail("DKG sign failed: \{e}")
    }
    assert_eq(
      @frost.prime_order_verify(p_ops, msg, sig, p_pub.verifying_key),
      Ok(true),
    )
  }
}

///|
test "Pedersen DKG cheater detection: invalid Round 1 PoK and forged Round 2 shares" {
  let ops = @frost.ristretto255_sha512()
  let r1_secrets : Array[@frost.DkgRound1Secret[@ristretto255.Scalar]] = []
  let r1_packages : Array[
    @frost.DkgRound1Package[@ristretto255.Scalar, @ristretto255.RistrettoPoint],
  ] = []
  for id = 1; id <= 5; id = id + 1 {
    let drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("cheat-dkg-\{id}"))
    let (sec, pkg) = match @frost.dkg_part1(ops, id, 5, 3, drbg) {
      Ok(v) => v
      Err(e) => fail("\{e}")
    }
    r1_secrets.push(sec)
    r1_packages.push(pkg)
  }

  // Tamper PoK of participants 4 and 2 (out of order) -> expect sorted [2, 4]
  let bad_r1 : Array[
    @frost.DkgRound1Package[@ristretto255.Scalar, @ristretto255.RistrettoPoint],
  ] = []
  for i = 0; i < 5; i = i + 1 {
    let pkg = r1_packages[i]
    if pkg.identifier == 2 || pkg.identifier == 4 {
      bad_r1.push({
        identifier: pkg.identifier,
        commitment: pkg.commitment,
        pok_r: pkg.pok_r,
        pok_mu: (ops.scalar_add)(pkg.pok_mu, (ops.scalar_one)()),
      })
    } else {
      bad_r1.push(pkg)
    }
  }
  match @frost.dkg_part2(ops, r1_secrets[0], bad_r1) {
    Err(@frost.FrostError::InvalidDkgProof(cheaters)) =>
      assert_eq(cheaters, [2, 4])
    Err(e) => fail("expected InvalidDkgProof([2, 4]), got Err(\{e})")
    Ok(_) => fail("expected InvalidDkgProof([2, 4]), got Ok")
  }

  // Valid Round 2, then forge Round 2 shares from participants 5 and 3 sent to P1
  let r2_secrets : Array[
    @frost.DkgRound2Secret[@ristretto255.Scalar, @ristretto255.RistrettoPoint],
  ] = []
  let p1_inbox : Array[@frost.DkgRound2Package[@ristretto255.Scalar]] = []
  for i = 0; i < 5; i = i + 1 {
    let (r2_sec, out_pkgs) = match
      @frost.dkg_part2(ops, r1_secrets[i], r1_packages) {
      Ok(v) => v
      Err(e) => fail("\{e}")
    }
    r2_secrets.push(r2_sec)
    for j = 0; j < out_pkgs.length(); j = j + 1 {
      let pkg = out_pkgs[j]
      if pkg.receiver == 1 {
        if pkg.sender == 3 || pkg.sender == 5 {
          p1_inbox.push({
            sender: pkg.sender,
            receiver: pkg.receiver,
            secret_share: (ops.scalar_add)(pkg.secret_share, (ops.scalar_one)()),
          })
        } else {
          p1_inbox.push(pkg)
        }
      }
    }
  }
  match @frost.dkg_part3(ops, r2_secrets[0], r1_packages, p1_inbox) {
    Err(@frost.FrostError::CheaterDetected(cheaters)) =>
      assert_eq(cheaters, [3, 5])
    Err(e) => fail("expected CheaterDetected([3, 5]), got Err(\{e})")
    Ok(_) => fail("expected CheaterDetected([3, 5]), got Ok")
  }
}

///|
test "Identifiable Abort in aggregate detects single and multiple cheaters (both suites)" {
  let msg = @crypto.ascii_bytes("identifiable abort test")

  // Ristretto255: 3-of-5 with 4 signers {1,2,3,5}, tamper P3 alone and {P2, P5} together
  let r_ops = @frost.ristretto255_sha512()
  let r_drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("abort-r255"))
  let (kps, pub_pkg, _) = match
    @frost.trusted_dealer_keygen(r_ops, r_drbg, 5, 3) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let indices : Array[Int32] = [0, 1, 2, 4]
  let nonces : Array[
    @frost.SigningNonces[@ristretto255.Scalar, @ristretto255.RistrettoPoint],
  ] = []
  let comms : Array[@frost.CommitmentEntry[@ristretto255.RistrettoPoint]] = []
  for i = 0; i < indices.length(); i = i + 1 {
    let kp = kps[indices[i]]
    let (n, c) = match @frost.commit(r_ops, kp.signing_share, r_drbg) {
      Ok(v) => v
      Err(e) => fail("\{e}")
    }
    nonces.push(n)
    comms.push({ identifier: kp.identifier, commitments: c, })
  }
  let shares : Array[@frost.SignatureShare[@ristretto255.Scalar]] = []
  for i = 0; i < indices.length(); i = i + 1 {
    let kp = kps[indices[i]]
    let s = match @frost.sign(r_ops, kp, nonces[i], msg, comms) {
      Ok(v) => v
      Err(e) => fail("\{e}")
    }
    shares.push(s)
  }
  // Single cheater: P3 (index 2 in shares)
  let single_bad : Array[@frost.SignatureShare[@ristretto255.Scalar]] = [
    shares[0],
    shares[1],
    {
      identifier: shares[2].identifier,
      share: (r_ops.scalar_add)(shares[2].share, (r_ops.scalar_one)()),
    },
    shares[3],
  ]
  match @frost.aggregate(r_ops, comms, msg, pub_pkg, single_bad) {
    Err(@frost.FrostError::CheaterDetected(cheaters)) =>
      assert_eq(cheaters, [3])
    Err(e) => fail("expected CheaterDetected([3]), got Err(\{e})")
    Ok(_) => fail("expected CheaterDetected([3]), got Ok")
  }
  // Multiple cheaters: P2 (+1) and P5 (+2) -> non-cancelling deltas trigger Identifiable Abort
  let two = (r_ops.scalar_from_u32)(2U)
  let multi_bad : Array[@frost.SignatureShare[@ristretto255.Scalar]] = [
    shares[0],
    {
      identifier: shares[1].identifier,
      share: (r_ops.scalar_add)(shares[1].share, (r_ops.scalar_one)()),
    },
    shares[2],
    {
      identifier: shares[3].identifier,
      share: (r_ops.scalar_add)(shares[3].share, two),
    },
  ]
  // Also verify individual share verification directly
  let pk2 = pub_pkg.verifying_share_for(2).unwrap()
  assert_eq(
    @frost.verify_signature_share(
      r_ops,
      2,
      pk2,
      comms[1].commitments,
      shares[1].share,
      comms,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(true),
  )
  assert_eq(
    @frost.verify_signature_share(
      r_ops,
      2,
      pk2,
      comms[1].commitments,
      multi_bad[1].share,
      comms,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(false),
  )
  match @frost.aggregate(r_ops, comms, msg, pub_pkg, multi_bad) {
    Err(@frost.FrostError::CheaterDetected(cheaters)) =>
      assert_eq(cheaters, [2, 5])
    Err(e) => fail("expected CheaterDetected([2, 5]), got Err(\{e})")
    Ok(_) => fail("expected CheaterDetected([2, 5]), got Ok")
  }

  // P-256 single cheater test
  let p_ops = @frost.p256_sha256()
  let p_drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("abort-p256"))
  let (pkps, ppub, _) = match
    @frost.trusted_dealer_keygen(p_ops, p_drbg, 3, 2) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let (pn1, pc1) = @frost.commit(p_ops, pkps[0].signing_share, p_drbg).unwrap()
  let (pn2, pc2) = @frost.commit(p_ops, pkps[1].signing_share, p_drbg).unwrap()
  let pcomms : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    { identifier: 1, commitments: pc1, },
    { identifier: 2, commitments: pc2, },
  ]
  let ps1 = @frost.sign(p_ops, pkps[0], pn1, msg, pcomms).unwrap()
  let ps2 = @frost.sign(p_ops, pkps[1], pn2, msg, pcomms).unwrap()
  let bad_ps1 : @frost.SignatureShare[@p256.Scalar] = {
    identifier: ps1.identifier,
    share: (p_ops.scalar_add)(ps1.share, (p_ops.scalar_one)()),
  }
  match @frost.aggregate(p_ops, pcomms, msg, ppub, [bad_ps1, ps2]) {
    Err(@frost.FrostError::CheaterDetected(cheaters)) =>
      assert_eq(cheaters, [1])
    Err(e) => fail("expected CheaterDetected([1]), got Err(\{e})")
    Ok(_) => fail("expected CheaterDetected([1]), got Ok")
  }
}

///|
test "Nonce one-time-use state machine, validation guards, and prime_order_sign" {
  let ops = @frost.p256_sha256()
  let drbg = @crypto.Drbg::from_seed(@crypto.ascii_bytes("guards-test"))
  let msg = @crypto.ascii_bytes("nonce reuse must fail")

  // Threshold validation
  assert_true(
    @frost.trusted_dealer_keygen(ops, drbg, 3, 1)
    is Err(@frost.FrostError::InvalidThreshold(_)),
  )
  assert_true(
    @frost.trusted_dealer_keygen(ops, drbg, 2, 3)
    is Err(@frost.FrostError::InvalidThreshold(_)),
  )

  let (kps, pub_pkg, _) = @frost.trusted_dealer_keygen(ops, drbg, 3, 2).unwrap()
  let (n1, c1) = @frost.commit(ops, kps[0].signing_share, drbg).unwrap()
  let (n2, c2) = @frost.commit(ops, kps[1].signing_share, drbg).unwrap()

  assert_false(n1.is_used())
  // Unsorted commitment list rejected
  let unsorted : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    { identifier: 2, commitments: c2, },
    { identifier: 1, commitments: c1, },
  ]
  assert_true(
    @frost.sign(ops, kps[0], n1, msg, unsorted)
    is Err(@frost.FrostError::UnsortedCommitments),
  )
  // Failed validation before consumption should not mark nonce used
  assert_false(n1.is_used())

  // Insufficient participants rejected
  let too_few : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    { identifier: 1, commitments: c1, },
  ]
  assert_true(
    @frost.sign(ops, kps[0], n1, msg, too_few)
    is Err(@frost.FrostError::InsufficientParticipants(1, 2)),
  )

  // Commitment mismatch rejected
  let mismatched : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    { identifier: 1, commitments: c2, },
    { identifier: 2, commitments: c2, },
  ]
  assert_true(
    @frost.sign(ops, kps[0], n1, msg, mismatched)
    is Err(@frost.FrostError::CommitmentMismatch(1)),
  )

  // Valid first sign consumes nonce; second sign MUST fail with NonceAlreadyUsed
  let valid_comms : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    { identifier: 1, commitments: c1, },
    { identifier: 2, commitments: c2, },
  ]
  assert_true(@frost.sign(ops, kps[0], n1, msg, valid_comms) is Ok(_))
  assert_true(n1.is_used())
  assert_true(
    @frost.sign(ops, kps[0], n1, msg, valid_comms)
    is Err(@frost.FrostError::NonceAlreadyUsed),
  )

  // Single-party prime_order_sign + serialize/deserialize + bad length rejection
  let sk = @frost.random_nonzero_scalar(ops, drbg)
  let pk = (ops.scalar_base_mul)(sk)
  let sig = @frost.prime_order_sign(ops, msg, sk, drbg).unwrap()
  assert_eq(@frost.prime_order_verify(ops, msg, sig, pk), Ok(true))
  let enc = @frost.serialize_signature(ops, sig).unwrap()
  assert_eq(enc.length(), 65)
  assert_true(
    @frost.deserialize_signature(ops, Bytes::make(64, b'\x00'))
    is Err(@frost.FrostError::InvalidSignatureLength(64, 65)),
  )
  let _ = pub_pkg
  let _ = n2
}

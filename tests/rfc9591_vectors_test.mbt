///|
/// Byte-exact IETF RFC 9591 Appendix E official test vectors for:
/// - Appendix E.3: FROST(ristretto255, SHA-512)
/// - Appendix E.4: FROST(P-256, SHA-256)

///|
fn vec_must_hex(hex : String) -> Bytes {
  match @crypto.hex_to_bytes(hex) {
    Ok(b) => b
    Err(e) => abort("invalid hex literal: \{e}")
  }
}

///|
fn[S, E] vec_must_scalar(ops : @frost.SuiteOps[S, E], hex : String) -> S {
  match (ops.deserialize_scalar)(vec_must_hex(hex)) {
    Ok(s) => s
    Err(e) => abort("invalid scalar literal: \{e}")
  }
}

///|
fn[S, E] vec_elem_hex(ops : @frost.SuiteOps[S, E], elem : E) -> String {
  match (ops.serialize_element)(elem) {
    Ok(b) => @crypto.bytes_to_hex(b)
    Err(e) => abort("element serialization failed: \{e}")
  }
}

///|
fn[S, E] vec_scalar_hex(ops : @frost.SuiteOps[S, E], scalar : S) -> String {
  @crypto.bytes_to_hex((ops.serialize_scalar)(scalar))
}

///|
test "RFC 9591 Appendix E.3: FROST(ristretto255, SHA-512) official vector" {
  let ops = @moonfrost.ristretto255_sha512()

  // Group input parameters (RFC 9591 Appendix E.3)
  let group_secret_key_hex = "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b"
  let expected_group_pk_hex = "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57"
  let msg = vec_must_hex("74657374")
  let coeff1_hex = "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02"

  // Expected signer shares
  let expected_p1_share_hex = "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e"
  let expected_p2_share_hex = "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01"
  let expected_p3_share_hex = "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04"

  // Round 1 randomness and expected outputs
  let p1_hiding_rand = vec_must_hex(
    "f595a133b4d95c6e1f79887220c8b275ce6277e7f68a6640e1e7140f9be2fb5c",
  )
  let p1_binding_rand = vec_must_hex(
    "34dd1001360e3513cb37bebfabe7be4a32c5bb91ba19fbd4360d039111f0fbdc",
  )
  let expected_p1_hiding_nonce = "214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03"
  let expected_p1_binding_nonce = "c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c"
  let expected_p1_hiding_comm = "965def4d0958398391fc06d8c2d72932608b1e6255226de4fb8d972dac15fd57"
  let expected_p1_binding_comm = "ec5170920660820007ae9e1d363936659ef622f99879898db86e5bf1d5bf2a14"
  let expected_p1_bf_input = "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57" +
    "2889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b03" +
    "3911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d46" +
    "03e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1" +
    "af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f" +
    "0100000000000000000000000000000000000000000000000000000000000000"
  let expected_p1_bf = "8967fd70fa06a58e5912603317fa94c77626395a695a0e4e4efc4476662eba0c"

  let p3_hiding_rand = vec_must_hex(
    "daa0cf42a32617786d390e0c7edfbf2efbd428037069357b5173ae61d6dd5d5e",
  )
  let p3_binding_rand = vec_must_hex(
    "b4387e72b2e4108ce4168931cc2c7fcce5f345a5297368952c18b5fc8473f050",
  )
  let expected_p3_hiding_nonce = "3f7927872b0f9051dd98dd73eb2b91494173bbe0feb65a3e7e58d3e2318fa40f"
  let expected_p3_binding_nonce = "ffd79445fb8030f0a3ddd3861aa4b42b618759282bfe24f1f9304c7009728305"
  let expected_p3_hiding_comm = "480e06e3de182bf83489c45d7441879932fd7b434a26af41455756264fbd5d6e"
  let expected_p3_binding_comm = "3064746dfd3c1862ef58fc68c706da287dd925066865ceacc816b3a28c7b363b"
  let expected_p3_bf_input = "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57" +
    "2889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b03" +
    "3911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d46" +
    "03e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1" +
    "af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f" +
    "0300000000000000000000000000000000000000000000000000000000000000"
  let expected_p3_bf = "f2c1bb7c33a10511158c2f1766a4a5fadf9f86f2a92692ed333128277cc31006"

  // Round 2 & Final signature expected outputs
  let expected_p1_sig_share = "9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09"
  let expected_p3_sig_share = "7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908"
  let expected_sig_hex = "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb2555" +
    "2164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802"

  // Step 1: Trusted dealer keygen + Feldman VSS verification
  let group_sk = vec_must_scalar(ops, group_secret_key_hex)
  let coeff1 = vec_must_scalar(ops, coeff1_hex)
  let (key_packages, pub_pkg, vss_comm) = match
    @frost.trusted_dealer_keygen_with_secret(ops, group_sk, [coeff1], 3) {
    Ok(v) => v
    Err(e) => fail("trusted_dealer_keygen_with_secret failed: \{e}")
  }
  assert_eq(key_packages.length(), 3)
  assert_eq(vec_elem_hex(ops, pub_pkg.verifying_key), expected_group_pk_hex)

  let kp1 = key_packages[0]
  let kp2 = key_packages[1]
  let kp3 = key_packages[2]
  assert_eq(kp1.identifier, 1)
  assert_eq(kp2.identifier, 2)
  assert_eq(kp3.identifier, 3)
  assert_eq(vec_scalar_hex(ops, kp1.signing_share), expected_p1_share_hex)
  assert_eq(vec_scalar_hex(ops, kp2.signing_share), expected_p2_share_hex)
  assert_eq(vec_scalar_hex(ops, kp3.signing_share), expected_p3_share_hex)

  // Verify all 3 shares against Feldman VSS commitment
  for i = 0; i < 3; i = i + 1 {
    let kp = key_packages[i]
    assert_eq(
      @frost.vss_verify(ops, kp.identifier, kp.signing_share, vss_comm),
      Ok(true),
    )
  }

  // Verify Shamir reconstruction from {P1, P3} recovers group_secret_key
  match
    @frost.secret_share_combine(
      ops,
      [(1, kp1.signing_share), (3, kp3.signing_share)],
      2,
    ) {
    Ok(recovered) =>
      assert_eq(vec_scalar_hex(ops, recovered), group_secret_key_hex)
    Err(e) => fail("secret_share_combine failed: \{e}")
  }

  // Step 2: Round 1 nonce generation & commitments for P1 and P3
  let p1_hn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp1.signing_share,
      p1_hiding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p1 hiding nonce failed: \{e}")
  }
  let p1_bn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp1.signing_share,
      p1_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p1 binding nonce failed: \{e}")
  }
  assert_eq(vec_scalar_hex(ops, p1_hn), expected_p1_hiding_nonce)
  assert_eq(vec_scalar_hex(ops, p1_bn), expected_p1_binding_nonce)

  let p3_hn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp3.signing_share,
      p3_hiding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p3 hiding nonce failed: \{e}")
  }
  let p3_bn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp3.signing_share,
      p3_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p3 binding nonce failed: \{e}")
  }
  assert_eq(vec_scalar_hex(ops, p3_hn), expected_p3_hiding_nonce)
  assert_eq(vec_scalar_hex(ops, p3_bn), expected_p3_binding_nonce)

  let (p1_nonces, p1_comms) = match
    @frost.commit_with_randomness(
      ops,
      kp1.signing_share,
      p1_hiding_rand,
      p1_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p1 commit_with_randomness failed: \{e}")
  }
  let (p3_nonces, p3_comms) = match
    @frost.commit_with_randomness(
      ops,
      kp3.signing_share,
      p3_hiding_rand,
      p3_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p3 commit_with_randomness failed: \{e}")
  }
  assert_eq(vec_elem_hex(ops, p1_comms.hiding), expected_p1_hiding_comm)
  assert_eq(vec_elem_hex(ops, p1_comms.binding), expected_p1_binding_comm)
  assert_eq(vec_elem_hex(ops, p3_comms.hiding), expected_p3_hiding_comm)
  assert_eq(vec_elem_hex(ops, p3_comms.binding), expected_p3_binding_comm)

  let commitment_list : Array[
    @frost.CommitmentEntry[@ristretto255.RistrettoPoint],
  ] = [
    @frost.CommitmentEntry::new(1, p1_comms),
    @frost.CommitmentEntry::new(3, p3_comms),
  ]

  // Step 3: Binding factor inputs & binding factors
  let bf_inputs = match
    @frost.compute_binding_factor_inputs(
      ops,
      pub_pkg.verifying_key,
      commitment_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => fail("compute_binding_factor_inputs failed: \{e}")
  }
  assert_eq(bf_inputs.length(), 2)
  assert_eq(bf_inputs[0].0, 1)
  assert_eq(@crypto.bytes_to_hex(bf_inputs[0].1), expected_p1_bf_input)
  assert_eq(bf_inputs[1].0, 3)
  assert_eq(@crypto.bytes_to_hex(bf_inputs[1].1), expected_p3_bf_input)

  let bfs = match
    @frost.compute_binding_factors(
      ops,
      pub_pkg.verifying_key,
      commitment_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => fail("compute_binding_factors failed: \{e}")
  }
  assert_eq(bfs.length(), 2)
  assert_eq(bfs[0].0, 1)
  assert_eq(vec_scalar_hex(ops, bfs[0].1), expected_p1_bf)
  assert_eq(bfs[1].0, 3)
  assert_eq(vec_scalar_hex(ops, bfs[1].1), expected_p3_bf)

  // Step 4: Round 2 signing & individual signature share verification
  assert_false(p1_nonces.is_used())
  assert_false(p3_nonces.is_used())
  let p1_sig_share = match
    @moonfrost.sign(ops, kp1, p1_nonces, msg, commitment_list) {
    Ok(v) => v
    Err(e) => fail("p1 sign failed: \{e}")
  }
  let p3_sig_share = match
    @moonfrost.sign(ops, kp3, p3_nonces, msg, commitment_list) {
    Ok(v) => v
    Err(e) => fail("p3 sign failed: \{e}")
  }
  assert_true(p1_nonces.is_used())
  assert_true(p3_nonces.is_used())
  assert_eq(vec_scalar_hex(ops, p1_sig_share.share), expected_p1_sig_share)
  assert_eq(vec_scalar_hex(ops, p3_sig_share.share), expected_p3_sig_share)

  assert_eq(
    @moonfrost.verify_signature_share(
      ops,
      1,
      kp1.verifying_share,
      p1_comms,
      p1_sig_share.share,
      commitment_list,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(true),
  )
  assert_eq(
    @moonfrost.verify_signature_share(
      ops,
      3,
      kp3.verifying_share,
      p3_comms,
      p3_sig_share.share,
      commitment_list,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(true),
  )

  // Step 5: Aggregation, 64-byte canonical serialization, deserialization & verification
  let sig = match
    @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, [
      p1_sig_share, p3_sig_share,
    ]) {
    Ok(v) => v
    Err(e) => fail("aggregate failed: \{e}")
  }
  let sig_bytes = match @moonfrost.serialize_signature(ops, sig) {
    Ok(b) => b
    Err(e) => fail("serialize_signature failed: \{e}")
  }
  assert_eq(sig_bytes.length(), 64)
  assert_eq(@crypto.bytes_to_hex(sig_bytes), expected_sig_hex)

  let decoded_sig = match @moonfrost.deserialize_signature(ops, sig_bytes) {
    Ok(s) => s
    Err(e) => fail("deserialize_signature failed: \{e}")
  }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg, decoded_sig, pub_pkg.verifying_key),
    Ok(true),
  )
}

///|
test "RFC 9591 Appendix E.4: FROST(P-256, SHA-256) official vector" {
  let ops = @moonfrost.p256_sha256()

  // Group input parameters (RFC 9591 Appendix E.4)
  let group_secret_key_hex = "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de"
  let expected_group_pk_hex = "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70"
  let msg = vec_must_hex("74657374")
  let coeff1_hex = "80f25e6c0709353e46bfbe882a11bdbb1f8097e46340eb8673b7e14556e6c3a4"

  // Expected signer shares
  let expected_p1_share_hex = "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731"
  let expected_p2_share_hex = "8d8e787bef0ff6c2f494ca45f4dad198c6bee01212d6c84067159c52e1863ad5"
  let expected_p3_share_hex = "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928"

  // Round 1 randomness and expected outputs
  let p1_hiding_rand = vec_must_hex(
    "ec4c891c85fee802a9d757a67d1252e7f4e5efb8a538991ac18fbd0e06fb6fd3",
  )
  let p1_binding_rand = vec_must_hex(
    "9334e29d09061223f69a09421715a347e4e6deba77444c8f42b0c833f80f4ef9",
  )
  let expected_p1_hiding_nonce = "9f0542a5ba879a58f255c09f06da7102ef6a2dec6279700c656d58394d8facd4"
  let expected_p1_binding_nonce = "6513dfe7429aa2fc972c69bb495b27118c45bbc6e654bb9dc9be55385b55c0d7"
  let expected_p1_hiding_comm = "0213b3e6298bf8ad46fd5e9389519a8665d63d98f4ec6a1fcca434e809d2d8070e"
  let expected_p1_binding_comm = "02188ff1390bf69374d7b272e454b1878ef10a6b6ea3ff36f114b300b4dbd5233b"
  let expected_p1_bf_input = "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70" +
    "825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d" +
    "178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd" +
    "0000000000000000000000000000000000000000000000000000000000000001"
  let expected_p1_bf = "7925f0d4693f204e6e59233e92227c7124664a99739d2c06b81cf64ddf90559e"

  let p3_hiding_rand = vec_must_hex(
    "c0451c5a0a5480d6c1f860e5db7d655233dca2669fd90ff048454b8ce983367b",
  )
  let p3_binding_rand = vec_must_hex(
    "2ba5f7793ae700e40e78937a82f407dd35e847e33d1e607b5c7eb6ed2a8ed799",
  )
  let expected_p3_hiding_nonce = "f73444a8972bcda9e506bbca3d2b1c083c10facdf4bb5d47fef7c2dc1d9f2a0d"
  let expected_p3_binding_nonce = "44c6a29075d6e7e4f8b97796205f9e22062e7835141470afe9417fd317c1c303"
  let expected_p3_hiding_comm = "033ac9a5fe4a8b57316ba1c34e8a6de453033b750e8984924a984eb67a11e73a3f"
  let expected_p3_binding_comm = "03a7a2480ee16199262e648aea3acab628a53e9b8c1945078f2ddfbdc98b7df369"
  let expected_p3_bf_input = "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70" +
    "825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d" +
    "178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd" +
    "0000000000000000000000000000000000000000000000000000000000000003"
  let expected_p3_bf = "e10d24a8a403723bcb6f9bb4c537f316593683b472f7a89f166630dde11822c4"

  // Round 2 & Final signature expected outputs
  let expected_p1_sig_share = "400308eaed7a2ddee02a265abe6a1cfe04d946ee8720768899619cfabe7a3aeb"
  let expected_p3_sig_share = "561da3c179edbb0502d941bb3e3ace3c37d122aaa46fb54499f15f3a3331de44"
  let expected_sig_hex = "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d" +
    "9620acac6767e8e3e3036815fca4eb3a3caa69992b902bcd3352fc34f1ac192f"

  // Step 1: Trusted dealer keygen + Feldman VSS verification
  let group_sk = vec_must_scalar(ops, group_secret_key_hex)
  let coeff1 = vec_must_scalar(ops, coeff1_hex)
  let (key_packages, pub_pkg, vss_comm) = match
    @frost.trusted_dealer_keygen_with_secret(ops, group_sk, [coeff1], 3) {
    Ok(v) => v
    Err(e) => fail("trusted_dealer_keygen_with_secret failed: \{e}")
  }
  assert_eq(key_packages.length(), 3)
  assert_eq(vec_elem_hex(ops, pub_pkg.verifying_key), expected_group_pk_hex)

  let kp1 = key_packages[0]
  let kp2 = key_packages[1]
  let kp3 = key_packages[2]
  assert_eq(kp1.identifier, 1)
  assert_eq(kp2.identifier, 2)
  assert_eq(kp3.identifier, 3)
  assert_eq(vec_scalar_hex(ops, kp1.signing_share), expected_p1_share_hex)
  assert_eq(vec_scalar_hex(ops, kp2.signing_share), expected_p2_share_hex)
  assert_eq(vec_scalar_hex(ops, kp3.signing_share), expected_p3_share_hex)

  // Verify all 3 shares against Feldman VSS commitment
  for i = 0; i < 3; i = i + 1 {
    let kp = key_packages[i]
    assert_eq(
      @frost.vss_verify(ops, kp.identifier, kp.signing_share, vss_comm),
      Ok(true),
    )
  }

  // Verify Shamir reconstruction from {P1, P3} recovers group_secret_key
  match
    @frost.secret_share_combine(
      ops,
      [(1, kp1.signing_share), (3, kp3.signing_share)],
      2,
    ) {
    Ok(recovered) =>
      assert_eq(vec_scalar_hex(ops, recovered), group_secret_key_hex)
    Err(e) => fail("secret_share_combine failed: \{e}")
  }

  // Step 2: Round 1 nonce generation & commitments for P1 and P3
  let p1_hn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp1.signing_share,
      p1_hiding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p1 hiding nonce failed: \{e}")
  }
  let p1_bn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp1.signing_share,
      p1_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p1 binding nonce failed: \{e}")
  }
  assert_eq(vec_scalar_hex(ops, p1_hn), expected_p1_hiding_nonce)
  assert_eq(vec_scalar_hex(ops, p1_bn), expected_p1_binding_nonce)

  let p3_hn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp3.signing_share,
      p3_hiding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p3 hiding nonce failed: \{e}")
  }
  let p3_bn = match
    @frost.nonce_generate_with_randomness(
      ops,
      kp3.signing_share,
      p3_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p3 binding nonce failed: \{e}")
  }
  assert_eq(vec_scalar_hex(ops, p3_hn), expected_p3_hiding_nonce)
  assert_eq(vec_scalar_hex(ops, p3_bn), expected_p3_binding_nonce)

  let (p1_nonces, p1_comms) = match
    @frost.commit_with_randomness(
      ops,
      kp1.signing_share,
      p1_hiding_rand,
      p1_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p1 commit_with_randomness failed: \{e}")
  }
  let (p3_nonces, p3_comms) = match
    @frost.commit_with_randomness(
      ops,
      kp3.signing_share,
      p3_hiding_rand,
      p3_binding_rand,
    ) {
    Ok(v) => v
    Err(e) => fail("p3 commit_with_randomness failed: \{e}")
  }
  assert_eq(vec_elem_hex(ops, p1_comms.hiding), expected_p1_hiding_comm)
  assert_eq(vec_elem_hex(ops, p1_comms.binding), expected_p1_binding_comm)
  assert_eq(vec_elem_hex(ops, p3_comms.hiding), expected_p3_hiding_comm)
  assert_eq(vec_elem_hex(ops, p3_comms.binding), expected_p3_binding_comm)

  let commitment_list : Array[@frost.CommitmentEntry[@p256.P256Point]] = [
    @frost.CommitmentEntry::new(1, p1_comms),
    @frost.CommitmentEntry::new(3, p3_comms),
  ]

  // Step 3: Binding factor inputs & binding factors
  let bf_inputs = match
    @frost.compute_binding_factor_inputs(
      ops,
      pub_pkg.verifying_key,
      commitment_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => fail("compute_binding_factor_inputs failed: \{e}")
  }
  assert_eq(bf_inputs.length(), 2)
  assert_eq(bf_inputs[0].0, 1)
  assert_eq(@crypto.bytes_to_hex(bf_inputs[0].1), expected_p1_bf_input)
  assert_eq(bf_inputs[1].0, 3)
  assert_eq(@crypto.bytes_to_hex(bf_inputs[1].1), expected_p3_bf_input)

  let bfs = match
    @frost.compute_binding_factors(
      ops,
      pub_pkg.verifying_key,
      commitment_list,
      msg,
    ) {
    Ok(v) => v
    Err(e) => fail("compute_binding_factors failed: \{e}")
  }
  assert_eq(bfs.length(), 2)
  assert_eq(bfs[0].0, 1)
  assert_eq(vec_scalar_hex(ops, bfs[0].1), expected_p1_bf)
  assert_eq(bfs[1].0, 3)
  assert_eq(vec_scalar_hex(ops, bfs[1].1), expected_p3_bf)

  // Step 4: Round 2 signing & individual signature share verification
  assert_false(p1_nonces.is_used())
  assert_false(p3_nonces.is_used())
  let p1_sig_share = match
    @moonfrost.sign(ops, kp1, p1_nonces, msg, commitment_list) {
    Ok(v) => v
    Err(e) => fail("p1 sign failed: \{e}")
  }
  let p3_sig_share = match
    @moonfrost.sign(ops, kp3, p3_nonces, msg, commitment_list) {
    Ok(v) => v
    Err(e) => fail("p3 sign failed: \{e}")
  }
  assert_true(p1_nonces.is_used())
  assert_true(p3_nonces.is_used())
  assert_eq(vec_scalar_hex(ops, p1_sig_share.share), expected_p1_sig_share)
  assert_eq(vec_scalar_hex(ops, p3_sig_share.share), expected_p3_sig_share)

  assert_eq(
    @moonfrost.verify_signature_share(
      ops,
      1,
      kp1.verifying_share,
      p1_comms,
      p1_sig_share.share,
      commitment_list,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(true),
  )
  assert_eq(
    @moonfrost.verify_signature_share(
      ops,
      3,
      kp3.verifying_share,
      p3_comms,
      p3_sig_share.share,
      commitment_list,
      pub_pkg.verifying_key,
      msg,
    ),
    Ok(true),
  )

  // Step 5: Aggregation, 65-byte canonical SEC1+scalar serialization, deserialization & verification
  let sig = match
    @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, [
      p1_sig_share, p3_sig_share,
    ]) {
    Ok(v) => v
    Err(e) => fail("aggregate failed: \{e}")
  }
  let sig_bytes = match @moonfrost.serialize_signature(ops, sig) {
    Ok(b) => b
    Err(e) => fail("serialize_signature failed: \{e}")
  }
  assert_eq(sig_bytes.length(), 65)
  assert_eq(@crypto.bytes_to_hex(sig_bytes), expected_sig_hex)

  let decoded_sig = match @moonfrost.deserialize_signature(ops, sig_bytes) {
    Ok(s) => s
    Err(e) => fail("deserialize_signature failed: \{e}")
  }
  assert_eq(
    @moonfrost.prime_order_verify(ops, msg, decoded_sig, pub_pkg.verifying_key),
    Ok(true),
  )
}

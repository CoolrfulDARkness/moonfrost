///|
fn hex_nibble(c : Int32) -> Int32 {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 97 + 10
  } else if c >= 65 && c <= 70 {
    c - 65 + 10
  } else {
    abort("invalid hex character")
  }
}

///|
fn hex_to_bytes(hex : String) -> Bytes {
  let nibbles : Array[Int32] = []
  for i = 0; i < hex.length(); i = i + 1 {
    let c = hex[i].to_int()
    if c == 32 || c == 10 || c == 13 || c == 9 {
      continue
    }
    nibbles.push(hex_nibble(c))
  }
  let n = nibbles.length() / 2
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((nibbles[2 * i] << 4) | nibbles[2 * i + 1]).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn bytes_to_hex(bytes : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < bytes.length(); i = i + 1 {
    let b = bytes[i].to_int()
    buf.write_char(digits[(b >> 4) & 0xF].unsafe_to_char())
    buf.write_char(digits[b & 0xF].unsafe_to_char())
  }
  buf.to_string()
}

///|
test "RFC 9496 Appendix A.1: multiples B[0..15] of generator" {
  let expected : Array[String] = [
    "0000000000000000000000000000000000000000000000000000000000000000", "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919", "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57", "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403", "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c", "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f", "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460", "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e", "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
  ]
  let g = @ristretto255.RistrettoPoint::generator()
  let mut acc = @ristretto255.RistrettoPoint::identity()
  for i = 0; i < 16; i = i + 1 {
    let enc = acc.encode()
    assert_eq(bytes_to_hex(enc), expected[i])
    // Check scalar_base_mul agrees with repeated addition
    let mul_pt = @ristretto255.RistrettoPoint::scalar_base_mul(
      @ristretto255.Scalar::from_u32(i.reinterpret_as_uint()),
    )
    assert_eq(mul_pt, acc)
    assert_eq(bytes_to_hex(mul_pt.encode()), expected[i])
    // Decode -> Eq -> Re-encode roundtrip
    let decoded = match @ristretto255.RistrettoPoint::decode(enc) {
      Ok(p) => p
      Err(e) => fail("failed to decode valid B[\{i}]: \{e}")
    }
    assert_eq(decoded, acc)
    assert_eq(decoded.ct_eq(acc), true)
    assert_eq(bytes_to_hex(decoded.encode()), expected[i])
    // Identity vs non-identity checks
    if i == 0 {
      assert_eq(acc.is_identity(), true)
      assert_true(acc.serialize_non_identity() is Err(_))
      assert_true(
        @ristretto255.RistrettoPoint::deserialize_non_identity(enc) is Err(_),
      )
    } else {
      assert_eq(acc.is_identity(), false)
      match acc.serialize_non_identity() {
        Ok(b) => assert_eq(bytes_to_hex(b), expected[i])
        Err(e) => fail("unexpected error: \{e}")
      }
      match @ristretto255.RistrettoPoint::deserialize_non_identity(enc) {
        Ok(p) => assert_eq(p, acc)
        Err(e) => fail("unexpected error: \{e}")
      }
    }
    acc = acc.add(g)
  }
}

///|
test "RFC 9496 Appendix A.2: all 29 invalid encodings must be rejected" {
  let invalid : Array[String] = [
    // Non-canonical field encodings (4)
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // Negative field elements (8)
     "0100000000000000000000000000000000000000000000000000000000000000", "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20", "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
    "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78", "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
    "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72", "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
    // Non-square x^2 (8)
     "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371", "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
    "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b", "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
    "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08", "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
    "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731", "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
    // Negative x * y value (8)
     "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e", "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
    "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e", "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
    "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b", "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
    "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e", "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
    // s = -1, which causes y = 0 (1)
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ]
  assert_eq(invalid.length(), 29)
  for i = 0; i < invalid.length(); i = i + 1 {
    let raw = hex_to_bytes(invalid[i])
    assert_true(@ristretto255.RistrettoPoint::decode(raw) is Err(_))
    assert_true(
      @ristretto255.RistrettoPoint::deserialize_non_identity(raw) is Err(_),
    )
  }
  // Wrong lengths must also be rejected
  assert_true(
    @ristretto255.RistrettoPoint::decode(Bytes::make(0, b'\x00')) is Err(_),
  )
  assert_true(
    @ristretto255.RistrettoPoint::decode(Bytes::make(31, b'\x00')) is Err(_),
  )
  assert_true(
    @ristretto255.RistrettoPoint::decode(Bytes::make(33, b'\x00')) is Err(_),
  )
}

///|
test "RFC 9496 Appendix A.3: all 11 uniform-bytes element derivation vectors" {
  let vectors : Array[(String, String)] = [
    (
      "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
      "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
    ),
    (
      "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
      "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b",
    ),
    (
      "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
      "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826",
    ),
    (
      "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
      "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a",
    ),
    (
      "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
      "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179",
    ),
    (
      "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
      "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628",
    ),
    (
      "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
      "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065",
    ),
    (
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000",
      "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f",
    ),
    (
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f",
    ),
    (
      "0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f",
    ),
    (
      "00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080",
      "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f",
    ),
  ]
  assert_eq(vectors.length(), 11)
  for i = 0; i < vectors.length(); i = i + 1 {
    let (inp, exp) = vectors[i]
    let pt = match
      @ristretto255.RistrettoPoint::from_uniform_bytes(hex_to_bytes(inp)) {
      Ok(p) => p
      Err(e) => fail("from_uniform_bytes failed on vector \{i}: \{e}")
    }
    assert_eq(bytes_to_hex(pt.encode()), exp)
    let dec = match @ristretto255.RistrettoPoint::decode(hex_to_bytes(exp)) {
      Ok(p) => p
      Err(e) => fail("decode failed on A.3 vector \{i}: \{e}")
    }
    assert_eq(pt, dec)
  }
  // Reject non-64-byte inputs
  assert_true(
    @ristretto255.RistrettoPoint::from_uniform_bytes(Bytes::make(63, b'\x00'))
    is Err(_),
  )
  assert_true(
    @ristretto255.RistrettoPoint::from_uniform_bytes(Bytes::make(65, b'\x00'))
    is Err(_),
  )
}

///|
test "Scalar field algebra, strict decoding, wide reduction, compare, invert" {
  let zero = @ristretto255.Scalar::zero()
  let one = @ristretto255.Scalar::one()
  let two = @ristretto255.Scalar::from_u32(2U)
  let three = @ristretto255.Scalar::from_u32(3U)
  let seven = @ristretto255.Scalar::from_u32(7U)
  assert_eq(zero.is_zero(), true)
  assert_eq(one.is_zero(), false)
  assert_eq(zero.neg(), zero)
  assert_eq(one.add(two), three)
  assert_eq(three.sub(two), one)
  assert_eq(one.sub(two), one.neg())
  assert_eq(one.add(one.neg()), zero)
  assert_eq(two.mul(three).add(one), seven)
  assert_eq(zero.compare(one), -1)
  assert_eq(one.compare(one), 0)
  assert_eq(seven.compare(three), 1)
  // Zero cannot be inverted
  assert_true(zero.invert() is Err(_))
  // Invert non-zero scalars
  let inv7 = match seven.invert() {
    Ok(v) => v
    Err(e) => fail("invert(7) failed: \{e}")
  }
  assert_eq(seven.mul(inv7), one)
  // l - 1 = -1 mod l
  let l_minus_1_bytes = hex_to_bytes(
    "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let l_bytes = hex_to_bytes(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let l_plus_1_bytes = hex_to_bytes(
    "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let all_ff_32 = hex_to_bytes(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
  let l_minus_1 = match
    @ristretto255.Scalar::from_bytes_strict(l_minus_1_bytes) {
    Ok(s) => s
    Err(e) => fail("l-1 should be valid: \{e}")
  }
  assert_eq(l_minus_1, one.neg())
  assert_eq(l_minus_1.add(one), zero)
  assert_eq(l_minus_1.mul(l_minus_1), one)
  assert_eq(l_minus_1.to_bytes(), l_minus_1_bytes)
  assert_eq(l_minus_1.compare(zero), 1)
  assert_eq(zero.compare(l_minus_1), -1)
  // Strict decoding rejects >= l and wrong lengths
  assert_true(@ristretto255.Scalar::from_bytes_strict(l_bytes) is Err(_))
  assert_true(@ristretto255.Scalar::from_bytes_strict(l_plus_1_bytes) is Err(_))
  assert_true(@ristretto255.Scalar::from_bytes_strict(all_ff_32) is Err(_))
  assert_true(
    @ristretto255.Scalar::from_bytes_strict(Bytes::make(31, b'\x00')) is Err(_),
  )
  assert_true(
    @ristretto255.Scalar::from_bytes_strict(Bytes::make(33, b'\x00')) is Err(_),
  )
  // Wide reduction tests:
  // l padded to 64 bytes -> 0
  let wide_l = hex_to_bytes(
    "edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
  )
  match @ristretto255.Scalar::from_bytes_mod_order_wide(wide_l) {
    Ok(s) => assert_eq(s, zero)
    Err(e) => fail("wide_l failed: \{e}")
  }
  // 2^256 (byte 32 = 1) -> R mod l = d6ec31748d98951d, c6ef5bf4737dcf70, fffffffffffffffe, 0fffffffffffffff
  let wide_2_256 = hex_to_bytes(
    "00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000",
  )
  match @ristretto255.Scalar::from_bytes_mod_order_wide(wide_2_256) {
    Ok(s) =>
      assert_eq(
        bytes_to_hex(s.to_bytes()),
        "1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f",
      )
    Err(e) => fail("wide 2^256 failed: \{e}")
  }
  // 2^512 - 1 (all 0xff) = (R^2 mod l) - 1 mod l
  let wide_all_ff = hex_to_bytes(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
  match @ristretto255.Scalar::from_bytes_mod_order_wide(wide_all_ff) {
    Ok(s) =>
      assert_eq(
        bytes_to_hex(s.to_bytes()),
        "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903",
      )
    Err(e) => fail("wide all ff failed: \{e}")
  }
  assert_true(
    @ristretto255.Scalar::from_bytes_mod_order_wide(Bytes::make(63, b'\x00'))
    is Err(_),
  )
  assert_true(
    @ristretto255.Scalar::from_bytes_mod_order_wide(Bytes::make(65, b'\x00'))
    is Err(_),
  )
  // Group order check: (l - 1) * G + G == Identity
  let g = @ristretto255.RistrettoPoint::generator()
  let neg_g = @ristretto255.RistrettoPoint::scalar_base_mul(l_minus_1)
  assert_eq(neg_g, g.neg())
  assert_eq(neg_g.add(g).is_identity(), true)
  assert_eq(g.sub(g).is_identity(), true)
  // Scalar multiplication distributivity: (a + b) * P == a * P + b * P and (a * b) * G == a * (b * G)
  let a = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let b = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let a_inv = match a.invert() {
    Ok(v) => v
    Err(e) => fail(e)
  }
  assert_eq(a.mul(a_inv), one)
  let p_a = @ristretto255.RistrettoPoint::scalar_base_mul(a)
  let p_b = @ristretto255.RistrettoPoint::scalar_base_mul(b)
  let p_ab_sum = @ristretto255.RistrettoPoint::scalar_base_mul(a.add(b))
  assert_eq(p_a.add(p_b), p_ab_sum)
  let p_ab_mul = @ristretto255.RistrettoPoint::scalar_base_mul(a.mul(b))
  assert_eq(p_a.scalar_mul(b), p_ab_mul)
  assert_eq(p_b.scalar_mul(a), p_ab_mul)
  assert_eq(p_a.scalar_mul(a_inv), g)
}

///|
test "RFC 9591 Appendix E.3: FROST(ristretto255, SHA-512) scalar & group cross-checks" {
  // Group secret key -> group public key
  let gsk = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail("gsk decode failed: \{e}")
  }
  let expected_gpk = "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57"
  let gpk = @ristretto255.RistrettoPoint::scalar_base_mul(gsk)
  assert_eq(bytes_to_hex(gpk.encode()), expected_gpk)

  // P1 hiding & binding nonces -> commitments
  let p1_hiding = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let p1_binding = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  assert_eq(
    bytes_to_hex(
      @ristretto255.RistrettoPoint::scalar_base_mul(p1_hiding).encode(),
    ),
    "965def4d0958398391fc06d8c2d72932608b1e6255226de4fb8d972dac15fd57",
  )
  assert_eq(
    bytes_to_hex(
      @ristretto255.RistrettoPoint::scalar_base_mul(p1_binding).encode(),
    ),
    "ec5170920660820007ae9e1d363936659ef622f99879898db86e5bf1d5bf2a14",
  )

  // P3 hiding & binding nonces -> commitments
  let p3_hiding = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "3f7927872b0f9051dd98dd73eb2b91494173bbe0feb65a3e7e58d3e2318fa40f",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let p3_binding = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "ffd79445fb8030f0a3ddd3861aa4b42b618759282bfe24f1f9304c7009728305",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  assert_eq(
    bytes_to_hex(
      @ristretto255.RistrettoPoint::scalar_base_mul(p3_hiding).encode(),
    ),
    "480e06e3de182bf83489c45d7441879932fd7b434a26af41455756264fbd5d6e",
  )
  assert_eq(
    bytes_to_hex(
      @ristretto255.RistrettoPoint::scalar_base_mul(p3_binding).encode(),
    ),
    "3064746dfd3c1862ef58fc68c706da287dd925066865ceacc816b3a28c7b363b",
  )

  // Bonus cross-check: Shamir share polynomial & Lagrange interpolation for {P1, P3}
  let coeff1 = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let s1 = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let s2 = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let s3 = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let two = @ristretto255.Scalar::from_u32(2U)
  let three = @ristretto255.Scalar::from_u32(3U)
  assert_eq(gsk.add(coeff1), s1)
  assert_eq(gsk.add(coeff1.mul(two)), s2)
  assert_eq(gsk.add(coeff1.mul(three)), s3)
  let inv2 = match two.invert() {
    Ok(v) => v
    Err(e) => fail(e)
  }
  // lambda_1 = 3 / (3 - 1) = 3/2, lambda_3 = 1 / (1 - 3) = -1/2
  let lambda1 = three.mul(inv2)
  let lambda3 = inv2.neg()
  assert_eq(lambda1.mul(s1).add(lambda3.mul(s3)), gsk)
  // Group commitment check: lambda1 * (s1 * G) + lambda3 * (s3 * G) == gpk
  let pk1 = @ristretto255.RistrettoPoint::scalar_base_mul(s1)
  let pk3 = @ristretto255.RistrettoPoint::scalar_base_mul(s3)
  assert_eq(pk1.scalar_mul(lambda1).add(pk3.scalar_mul(lambda3)), gpk)
}

///|
test "Ristretto255 equivalence across distinct internal representations and edge cases" {
  let g = @ristretto255.RistrettoPoint::generator()
  let id = @ristretto255.RistrettoPoint::identity()
  let zero = @ristretto255.Scalar::zero()
  let one = @ristretto255.Scalar::one()
  let two = @ristretto255.Scalar::from_u32(2U)
  let neg_one = one.neg()
  // Distinct representations of identity
  let id_from_sub = g.sub(g)
  let id_from_mul0 = g.scalar_mul(zero)
  let id_from_order = g.scalar_mul(neg_one).add(g)
  let id_from_decode = match
    @ristretto255.RistrettoPoint::decode(Bytes::make(32, b'\x00')) {
    Ok(p) => p
    Err(e) => fail(e)
  }
  assert_eq(id, id_from_sub)
  assert_eq(id, id_from_mul0)
  assert_eq(id, id_from_order)
  assert_eq(id, id_from_decode)
  assert_eq(id_from_sub.is_identity(), true)
  assert_eq(id_from_order.encode(), Bytes::make(32, b'\x00'))
  // Distinct representations of 2*G
  let p_add = g.add(g)
  let p_mul = g.scalar_mul(two)
  let p_dec = match @ristretto255.RistrettoPoint::decode(p_add.encode()) {
    Ok(p) => p
    Err(e) => fail(e)
  }
  assert_eq(p_add, p_mul)
  assert_eq(p_add, p_dec)
  assert_eq(p_mul, p_dec)
  assert_eq(p_add.ct_eq(g), false)
  // Scalar (-1)^(-1) == -1 and multi-limb compare
  let inv_neg1 = match neg_one.invert() {
    Ok(v) => v
    Err(e) => fail(e)
  }
  assert_eq(inv_neg1, neg_one)
  let neg_two = two.neg()
  assert_eq(neg_two.compare(neg_one), -1)
  assert_eq(neg_one.compare(neg_two), 1)
  assert_eq(neg_one.add(neg_one), neg_two)
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let p = parts[i]
    for j = 0; j < p.length(); j = j + 1 {
      out[offset + j] = p[j]
    }
    offset = offset + p.length()
  }
  Bytes::from_array(out)
}

///|
test "RFC 9591 Appendix E.3: H1/H2/H3/H4/H5, full signature verification, and H_dkg" {
  assert_eq(@ristretto255.CONTEXT_STRING, "FROST-RISTRETTO255-SHA512-v1")
  assert_eq(@ristretto255.NE, 32)
  assert_eq(@ristretto255.NS, 32)

  let msg = hex_to_bytes("74657374") // "test"
  let gpk_bytes = hex_to_bytes(
    "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
  )
  let gpk = match @ristretto255.RistrettoPoint::decode(gpk_bytes) {
    Ok(p) => p
    Err(e) => fail(e)
  }

  // P1 & P3 shares and nonce randomness
  let p1_share = hex_to_bytes(
    "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
  )
  let p3_share = hex_to_bytes(
    "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
  )
  let p1_hiding_rand = hex_to_bytes(
    "f595a133b4d95c6e1f79887220c8b275ce6277e7f68a6640e1e7140f9be2fb5c",
  )
  let p1_binding_rand = hex_to_bytes(
    "34dd1001360e3513cb37bebfabe7be4a32c5bb91ba19fbd4360d039111f0fbdc",
  )
  let p3_hiding_rand = hex_to_bytes(
    "daa0cf42a32617786d390e0c7edfbf2efbd428037069357b5173ae61d6dd5d5e",
  )
  let p3_binding_rand = hex_to_bytes(
    "b4387e72b2e4108ce4168931cc2c7fcce5f345a5297368952c18b5fc8473f050",
  )

  // H3: verify P1 & P3 hiding_nonce and binding_nonce byte-for-byte
  let p1_hiding_nonce = @ristretto255.h3(
    concat_bytes([p1_hiding_rand, p1_share]),
  )
  let p1_binding_nonce = @ristretto255.h3(
    concat_bytes([p1_binding_rand, p1_share]),
  )
  let p3_hiding_nonce = @ristretto255.h3(
    concat_bytes([p3_hiding_rand, p3_share]),
  )
  let p3_binding_nonce = @ristretto255.h3(
    concat_bytes([p3_binding_rand, p3_share]),
  )
  assert_eq(
    bytes_to_hex(p1_hiding_nonce.to_bytes()),
    "214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03",
  )
  assert_eq(
    bytes_to_hex(p1_binding_nonce.to_bytes()),
    "c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c",
  )
  assert_eq(
    bytes_to_hex(p3_hiding_nonce.to_bytes()),
    "3f7927872b0f9051dd98dd73eb2b91494173bbe0feb65a3e7e58d3e2318fa40f",
  )
  assert_eq(
    bytes_to_hex(p3_binding_nonce.to_bytes()),
    "ffd79445fb8030f0a3ddd3861aa4b42b618759282bfe24f1f9304c7009728305",
  )

  // H4 & H5: build binding_factor_input for P1 and P3 and verify byte-for-byte
  let d1 = @ristretto255.RistrettoPoint::scalar_base_mul(p1_hiding_nonce)
  let e1 = @ristretto255.RistrettoPoint::scalar_base_mul(p1_binding_nonce)
  let d3 = @ristretto255.RistrettoPoint::scalar_base_mul(p3_hiding_nonce)
  let e3 = @ristretto255.RistrettoPoint::scalar_base_mul(p3_binding_nonce)
  let id1 = @ristretto255.Scalar::from_u32(1U).to_bytes()
  let id3 = @ristretto255.Scalar::from_u32(3U).to_bytes()
  let encoded_commitments = concat_bytes([
    id1,
    d1.encode(),
    e1.encode(),
    id3,
    d3.encode(),
    e3.encode(),
  ])
  let msg_hash = @ristretto255.h4(msg)
  let com_hash = @ristretto255.h5(encoded_commitments)
  assert_eq(msg_hash.length(), 64)
  assert_eq(com_hash.length(), 64)
  let rho_prefix = concat_bytes([gpk_bytes, msg_hash, com_hash])
  let p1_bf_input = concat_bytes([rho_prefix, id1])
  let p3_bf_input = concat_bytes([rho_prefix, id3])
  assert_eq(
    bytes_to_hex(p1_bf_input),
    "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f572889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b033911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d4603e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(
    bytes_to_hex(p3_bf_input),
    "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f572889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b033911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d4603e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f0300000000000000000000000000000000000000000000000000000000000000",
  )

  // H1: verify P1 & P3 binding_factor byte-for-byte
  let rho1 = @ristretto255.h1(p1_bf_input)
  let rho3 = @ristretto255.h1(p3_bf_input)
  assert_eq(
    bytes_to_hex(rho1.to_bytes()),
    "8967fd70fa06a58e5912603317fa94c77626395a695a0e4e4efc4476662eba0c",
  )
  assert_eq(
    bytes_to_hex(rho3.to_bytes()),
    "f2c1bb7c33a10511158c2f1766a4a5fadf9f86f2a92692ed333128277cc31006",
  )

  // Group commitment R = D1 + rho1*E1 + D3 + rho3*E3 must match sig[0..32]
  let group_r = d1.add(e1.scalar_mul(rho1)).add(d3).add(e3.scalar_mul(rho3))
  let expected_r = "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb2555"
  assert_eq(bytes_to_hex(group_r.encode()), expected_r)

  // H2: verify full FROST signature equation z*G == R + H2(R || Y || msg)*Y
  let z1 = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let z3 = match
    @ristretto255.Scalar::from_bytes_strict(
      hex_to_bytes(
        "7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908",
      ),
    ) {
    Ok(s) => s
    Err(e) => fail(e)
  }
  let z_agg = z1.add(z3)
  assert_eq(
    bytes_to_hex(z_agg.to_bytes()),
    "2164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802",
  )
  let chal = @ristretto255.h2(concat_bytes([group_r.encode(), gpk_bytes, msg]))
  let lhs = @ristretto255.RistrettoPoint::scalar_base_mul(z_agg)
  let rhs = group_r.add(gpk.scalar_mul(chal))
  assert_eq(lhs, rhs)

  // H_dkg: domain separation check against H1, H2, H3
  let dkg_s = @ristretto255.h_dkg(msg)
  assert_eq(dkg_s.is_zero(), false)
  assert_eq(dkg_s == @ristretto255.h1(msg), false)
  assert_eq(dkg_s == @ristretto255.h2(msg), false)
  assert_eq(dkg_s == @ristretto255.h3(msg), false)
  assert_eq(dkg_s, @ristretto255.h_dkg(msg))
}

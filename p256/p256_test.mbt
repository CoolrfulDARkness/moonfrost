// Tests for CoolrfulDARkness/moonfrost/p256:
// - Base field F_p operations, boundaries, strict decoding, inv, sqrt
// - Scalar field F_n operations, boundaries, strict decoding, invert, compare, 48-byte wide reduction
// - Complete projective addition (RCB4/RCB6) edge cases & curve axioms
// - RFC 9591 Appendix E.4 FROST(P-256, SHA-256) cross-verification
// - SEC1 compressed serialization / deserialization & invalid point rejection

///|
fn hex_nibble(c : Int32) -> Int32 {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 87
  } else if c >= 65 && c <= 70 {
    c - 55
  } else {
    abort("invalid hex char")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let len = s.length()
  if len % 2 != 0 {
    abort("odd hex length")
  }
  let out_len = len / 2
  Bytes::makei(out_len, fn(i) {
    let hi = hex_nibble(s[i * 2].to_int())
    let lo = hex_nibble(s[i * 2 + 1].to_int())
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let b = data[i].to_int()
    buf.write_char(digits[(b >> 4) & 0x0f].unsafe_to_char())
    buf.write_char(digits[b & 0x0f].unsafe_to_char())
  }
  buf.to_string()
}

///|
fn must_field(hex : String) -> @p256.FieldElement {
  match @p256.FieldElement::from_bytes_be_strict(from_hex(hex)) {
    Ok(v) => v
    Err(e) => abort(e)
  }
}

///|
fn must_scalar(hex : String) -> @p256.Scalar {
  match @p256.Scalar::from_bytes_strict(from_hex(hex)) {
    Ok(v) => v
    Err(e) => abort(e)
  }
}

///|
fn must_point(hex : String) -> @p256.P256Point {
  match @p256.P256Point::deserialize_compressed(from_hex(hex)) {
    Ok(v) => v
    Err(e) => abort(e)
  }
}

///|
fn must_serialize(pt : @p256.P256Point) -> String {
  match pt.serialize_compressed() {
    Ok(b) => to_hex(b)
    Err(e) => abort(e)
  }
}

///|
test "field arithmetic, inv, sqrt, strict decoding" {
  let zero = @p256.FieldElement::zero()
  let one = @p256.FieldElement::one()
  assert_true(zero.is_zero())
  assert_false(one.is_zero())
  assert_false(zero.is_odd())
  assert_true(one.is_odd())
  assert_eq(zero.neg(), zero)
  assert_eq(one.add(one.neg()), zero)

  // p - 1
  let p_minus_1 = must_field(
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
  )
  assert_eq(p_minus_1.add(one), zero)
  assert_eq(zero.sub(one), p_minus_1)
  assert_eq(p_minus_1.neg(), one)
  assert_false(p_minus_1.is_odd())
  assert_eq(
    to_hex(p_minus_1.to_bytes_be()),
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
  )

  // Reject p, p + 1, 0xff..ff, and wrong lengths
  assert_true(
    @p256.FieldElement::from_bytes_be_strict(
      from_hex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.FieldElement::from_bytes_be_strict(
      from_hex(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.FieldElement::from_bytes_be_strict(
      from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.FieldElement::from_bytes_be_strict(from_hex("00")) is Err(_),
  )

  // Generator coordinates satisfy y^2 = x^3 - 3x + b
  let gx = must_field(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  )
  let gy = must_field(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  )
  let b = must_field(
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
  )
  let lhs = gy.sq()
  let rhs = gx.sq().mul(gx).sub(gx.add(gx).add(gx)).add(b)
  assert_eq(lhs, rhs)

  // inv
  assert_eq(gx.mul(gx.inv()), one)
  assert_eq(gy.mul(gy.inv()), one)
  assert_eq(p_minus_1.inv(), p_minus_1)
  assert_eq(zero.inv(), zero)

  // sqrt: valid square root and non-QR
  let root = match rhs.sqrt() {
    Some(r) => r
    None => abort("expected square root for Gy^2")
  }
  assert_eq(root.sq(), rhs)
  assert_true(root.ct_eq(gy) || root.ct_eq(gy.neg()))

  // x = 1 gives x^3 - 3x + b = b - 2 which is a non-QR mod p
  let non_qr = one.sub(one.add(one).add(one)).add(b)
  assert_true(non_qr.sqrt() is None)

  // ct_select
  assert_eq(@p256.FieldElement::ct_select(0xffffffffffffffffUL, gx, gy), gx)
  assert_eq(@p256.FieldElement::ct_select(0UL, gx, gy), gy)
}

///|
test "scalar arithmetic, invert, compare, strict and wide decoding" {
  let zero = @p256.Scalar::zero()
  let one = @p256.Scalar::one()
  let two = @p256.Scalar::from_u32(2U)
  let three = @p256.Scalar::from_u32(3U)

  assert_true(zero.is_zero())
  assert_false(one.is_zero())
  assert_eq(one.add(two), three)
  assert_eq(three.sub(two), one)
  assert_eq(zero.neg(), zero)
  assert_eq(three.add(three.neg()), zero)
  assert_eq(two.mul(three), @p256.Scalar::from_u32(6U))

  // n - 1
  let n_minus_1 = must_scalar(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
  )
  assert_eq(n_minus_1.add(one), zero)
  assert_eq(zero.sub(one), n_minus_1)
  assert_eq(n_minus_1.neg(), one)
  assert_eq(
    to_hex(n_minus_1.to_bytes()),
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
  )

  // Reject >= n and bad lengths
  assert_true(
    @p256.Scalar::from_bytes_strict(
      from_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.Scalar::from_bytes_strict(
      from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
    )
    is Err(_),
  )
  assert_true(@p256.Scalar::from_bytes_strict(from_hex("010203")) is Err(_))

  // compare
  assert_eq(zero.compare(zero), 0)
  assert_eq(zero.compare(one), -1)
  assert_eq(one.compare(zero), 1)
  assert_eq(one.compare(n_minus_1), -1)
  assert_eq(n_minus_1.compare(one), 1)
  assert_eq(n_minus_1.compare(n_minus_1), 0)

  // invert
  assert_true(zero.invert() is Err(_))
  let inv_one = match one.invert() {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(inv_one, one)
  let inv_nm1 = match n_minus_1.invert() {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(inv_nm1, n_minus_1)
  let s_test = must_scalar(
    "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
  )
  let s_inv = match s_test.invert() {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(s_test.mul(s_inv), one)

  // 48-byte wide reduction (RFC 9380 L=48)
  assert_true(@p256.Scalar::from_wide_be_bytes(from_hex("00")) is Err(_))
  assert_true(
    @p256.Scalar::from_wide_be_bytes(
      from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
    )
    is Err(_),
  )

  // All zeros (48 bytes) -> 0
  let w_zero = match
    @p256.Scalar::from_wide_be_bytes(
      from_hex(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      ),
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(w_zero, zero)

  // 2^256 mod n
  let w_2_256 = match
    @p256.Scalar::from_wide_be_bytes(
      from_hex(
        "000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
      ),
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(
    to_hex(w_2_256.to_bytes()),
    "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf",
  )

  // Carry boundary: (n << 128) + (n - 1) mod n == n - 1
  let w_carry = match
    @p256.Scalar::from_wide_be_bytes(
      from_hex(
        "ffffffff000000010000000000000000bce6faaca7179e85f3b9cac2fc632550bce6faada7179e84f3b9cac2fc632550",
      ),
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(w_carry, n_minus_1)

  // Pattern 00 01 ... 2f mod n
  let w_pat = match
    @p256.Scalar::from_wide_be_bytes(
      from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
      ),
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(
    to_hex(w_pat.to_bytes()),
    "18185bb801b6065828af9bb667d107070b65183fa249175ca5990e37966adde8",
  )

  // Max 48-byte value 0xff * 48 mod n
  let w_max = match
    @p256.Scalar::from_wide_be_bytes(
      from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(
    to_hex(w_max.to_bytes()),
    "431905529c0166ce652e96b7ccca0a99679b73e19ad16947f01cf013fc632550",
  )
}

///|
test "point complete addition edge cases and group order n*G = O" {
  let id = @p256.P256Point::identity()
  let g = @p256.P256Point::generator()
  let neg_g = g.neg()

  // Complete addition & doubling edge cases
  assert_true(id.is_identity())
  assert_false(g.is_identity())
  assert_true(id.add(id).is_identity())
  assert_eq(id.add(id), id)
  assert_eq(id.double(), id)
  assert_eq(id.neg(), id)
  assert_eq(id.add(g), g)
  assert_eq(g.add(id), g)
  assert_true(g.add(neg_g).is_identity())
  assert_true(neg_g.add(g).is_identity())
  assert_true(g.sub(g).is_identity())
  assert_eq(g.add(neg_g), id)

  // G + G == 2*G == scalar_base_mul(2)
  let g2_add = g.add(g)
  let g2_dbl = g.double()
  let g2_mul = @p256.P256Point::scalar_base_mul(@p256.Scalar::from_u32(2U))
  assert_eq(g2_add, g2_dbl)
  assert_eq(g2_add, g2_mul)

  // 3*G consistency
  let g3_a = g2_dbl.add(g)
  let g3_b = g.add(g2_add)
  let g3_mul = @p256.P256Point::scalar_base_mul(@p256.Scalar::from_u32(3U))
  assert_eq(g3_a, g3_b)
  assert_eq(g3_a, g3_mul)

  // 0*G == O, 1*G == G, k*O == O
  assert_true(
    @p256.P256Point::scalar_base_mul(@p256.Scalar::zero()).is_identity(),
  )
  assert_eq(@p256.P256Point::scalar_base_mul(@p256.Scalar::one()), g)
  assert_true(id.scalar_mul(@p256.Scalar::from_u32(42U)).is_identity())

  // n * G == O checked via (n - 1)*G + G == O and (n - 1)*G == -G
  let n_minus_1 = must_scalar(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
  )
  let nm1_g = @p256.P256Point::scalar_base_mul(n_minus_1)
  assert_eq(nm1_g, neg_g)
  assert_true(nm1_g.add(g).is_identity())

  // Also check 2 * ((n - 1) / 2) * G + G == n * G == O
  let half_nm1 = must_scalar(
    "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
  )
  let half_pt = @p256.P256Point::scalar_base_mul(half_nm1)
  assert_true(half_pt.add(half_pt).add(g).is_identity())

  // Homomorphism & associativity: (a + b)*G == a*G + b*G and (a*b)*G == a*(b*G)
  let a = must_scalar(
    "9f0542a5ba879a58f255c09f06da7102ef6a2dec6279700c656d58394d8facd4",
  )
  let b = must_scalar(
    "6513dfe7429aa2fc972c69bb495b27118c45bbc6e654bb9dc9be55385b55c0d7",
  )
  let pa = @p256.P256Point::scalar_base_mul(a)
  let pb = @p256.P256Point::scalar_base_mul(b)
  assert_eq(@p256.P256Point::scalar_base_mul(a.add(b)), pa.add(pb))
  assert_eq(@p256.P256Point::scalar_base_mul(a.mul(b)), pb.scalar_mul(a))

  // Generator SEC1 compressed roundtrip
  let g_hex = must_serialize(g)
  assert_eq(
    g_hex, "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  )
  assert_eq(must_point(g_hex), g)
}

///|
test "RFC 9591 Appendix E.4 FROST(P-256, SHA-256) vectors" {
  // group_secret_key -> group_public_key
  let gsk = must_scalar(
    "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
  )
  let expected_gpk = "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70"
  let gpk = @p256.P256Point::scalar_base_mul(gsk)
  assert_eq(must_serialize(gpk), expected_gpk)
  assert_eq(must_point(expected_gpk), gpk)

  // P1 hiding_nonce -> P1 hiding_nonce_commitment
  let p1_hiding = must_scalar(
    "9f0542a5ba879a58f255c09f06da7102ef6a2dec6279700c656d58394d8facd4",
  )
  let expected_p1_d = "0213b3e6298bf8ad46fd5e9389519a8665d63d98f4ec6a1fcca434e809d2d8070e"
  let p1_d = @p256.P256Point::scalar_base_mul(p1_hiding)
  assert_eq(must_serialize(p1_d), expected_p1_d)
  assert_eq(must_point(expected_p1_d), p1_d)

  // P1 binding_nonce -> P1 binding_nonce_commitment
  let p1_binding = must_scalar(
    "6513dfe7429aa2fc972c69bb495b27118c45bbc6e654bb9dc9be55385b55c0d7",
  )
  let expected_p1_e = "02188ff1390bf69374d7b272e454b1878ef10a6b6ea3ff36f114b300b4dbd5233b"
  let p1_e = @p256.P256Point::scalar_base_mul(p1_binding)
  assert_eq(must_serialize(p1_e), expected_p1_e)
  assert_eq(must_point(expected_p1_e), p1_e)

  // P3 hiding_nonce -> P3 hiding_nonce_commitment
  let p3_hiding = must_scalar(
    "f73444a8972bcda9e506bbca3d2b1c083c10facdf4bb5d47fef7c2dc1d9f2a0d",
  )
  let expected_p3_d = "033ac9a5fe4a8b57316ba1c34e8a6de453033b750e8984924a984eb67a11e73a3f"
  let p3_d = @p256.P256Point::scalar_base_mul(p3_hiding)
  assert_eq(must_serialize(p3_d), expected_p3_d)
  assert_eq(must_point(expected_p3_d), p3_d)

  // P3 binding_nonce -> P3 binding_nonce_commitment
  let p3_binding = must_scalar(
    "44c6a29075d6e7e4f8b97796205f9e22062e7835141470afe9417fd317c1c303",
  )
  let expected_p3_e = "03a7a2480ee16199262e648aea3acab628a53e9b8c1945078f2ddfbdc98b7df369"
  let p3_e = @p256.P256Point::scalar_base_mul(p3_binding)
  assert_eq(must_serialize(p3_e), expected_p3_e)
  assert_eq(must_point(expected_p3_e), p3_e)

  // Cross-check group commitment R = D1 + rho1*E1 + D3 + rho3*E3 against E.4 sig prefix
  let p1_rho = must_scalar(
    "7925f0d4693f204e6e59233e92227c7124664a99739d2c06b81cf64ddf90559e",
  )
  let p3_rho = must_scalar(
    "e10d24a8a403723bcb6f9bb4c537f316593683b472f7a89f166630dde11822c4",
  )
  let group_r = p1_d
    .add(p1_e.scalar_mul(p1_rho))
    .add(p3_d)
    .add(p3_e.scalar_mul(p3_rho))
  assert_eq(
    must_serialize(group_r),
    "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d",
  )
}

///|
fn concat_parts(parts : Array[Bytes]) -> Bytes {
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
test "RFC 9591 Appendix E.4 H1/H2/H3/H4/H5 and H_dkg suite hashes" {
  assert_eq(@p256.CONTEXT_STRING, "FROST-P256-SHA256-v1")
  assert_eq(@p256.NE, 33)
  assert_eq(@p256.NS, 32)

  // E.4 participant shares & nonce randomness
  let p1_share = from_hex(
    "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
  )
  let p3_share = from_hex(
    "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928",
  )
  let p1_hiding_rand = from_hex(
    "ec4c891c85fee802a9d757a67d1252e7f4e5efb8a538991ac18fbd0e06fb6fd3",
  )
  let p1_binding_rand = from_hex(
    "9334e29d09061223f69a09421715a347e4e6deba77444c8f42b0c833f80f4ef9",
  )
  let p3_hiding_rand = from_hex(
    "c0451c5a0a5480d6c1f860e5db7d655233dca2669fd90ff048454b8ce983367b",
  )
  let p3_binding_rand = from_hex(
    "2ba5f7793ae700e40e78937a82f407dd35e847e33d1e607b5c7eb6ed2a8ed799",
  )

  // Verify H3: nonce_generate(sk) = H3(random_bytes || SerializeScalar(sk))
  let p1_hiding_nonce = @p256.h3(concat_parts([p1_hiding_rand, p1_share]))
  assert_eq(
    to_hex(p1_hiding_nonce.to_bytes()),
    "9f0542a5ba879a58f255c09f06da7102ef6a2dec6279700c656d58394d8facd4",
  )
  let p1_binding_nonce = @p256.h3(concat_parts([p1_binding_rand, p1_share]))
  assert_eq(
    to_hex(p1_binding_nonce.to_bytes()),
    "6513dfe7429aa2fc972c69bb495b27118c45bbc6e654bb9dc9be55385b55c0d7",
  )
  let p3_hiding_nonce = @p256.h3(concat_parts([p3_hiding_rand, p3_share]))
  assert_eq(
    to_hex(p3_hiding_nonce.to_bytes()),
    "f73444a8972bcda9e506bbca3d2b1c083c10facdf4bb5d47fef7c2dc1d9f2a0d",
  )
  let p3_binding_nonce = @p256.h3(concat_parts([p3_binding_rand, p3_share]))
  assert_eq(
    to_hex(p3_binding_nonce.to_bytes()),
    "44c6a29075d6e7e4f8b97796205f9e22062e7835141470afe9417fd317c1c303",
  )

  // Verify H4 (msg pre-hash) and H5 (encoded commitment list hash) -> binding_factor_input
  let gpk_bytes = from_hex(
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",
  )
  let msg = from_hex("74657374")
  let id1_bytes = @p256.Scalar::from_u32(1U).to_bytes()
  let id3_bytes = @p256.Scalar::from_u32(3U).to_bytes()
  let p1_d_bytes = from_hex(
    "0213b3e6298bf8ad46fd5e9389519a8665d63d98f4ec6a1fcca434e809d2d8070e",
  )
  let p1_e_bytes = from_hex(
    "02188ff1390bf69374d7b272e454b1878ef10a6b6ea3ff36f114b300b4dbd5233b",
  )
  let p3_d_bytes = from_hex(
    "033ac9a5fe4a8b57316ba1c34e8a6de453033b750e8984924a984eb67a11e73a3f",
  )
  let p3_e_bytes = from_hex(
    "03a7a2480ee16199262e648aea3acab628a53e9b8c1945078f2ddfbdc98b7df369",
  )

  let msg_hash = @p256.h4(msg)
  assert_eq(msg_hash.length(), 32)
  let encoded_commitments = concat_parts([
    id1_bytes, p1_d_bytes, p1_e_bytes, id3_bytes, p3_d_bytes, p3_e_bytes,
  ])
  let encoded_comm_hash = @p256.h5(encoded_commitments)
  assert_eq(encoded_comm_hash.length(), 32)

  let p1_rho_input = concat_parts([
    gpk_bytes, msg_hash, encoded_comm_hash, id1_bytes,
  ])
  assert_eq(
    to_hex(p1_rho_input),
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd0000000000000000000000000000000000000000000000000000000000000001",
  )
  let p3_rho_input = concat_parts([
    gpk_bytes, msg_hash, encoded_comm_hash, id3_bytes,
  ])
  assert_eq(
    to_hex(p3_rho_input),
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd0000000000000000000000000000000000000000000000000000000000000003",
  )

  // Verify H1: binding_factor = H1(binding_factor_input)
  let p1_rho = @p256.h1(p1_rho_input)
  assert_eq(
    to_hex(p1_rho.to_bytes()),
    "7925f0d4693f204e6e59233e92227c7124664a99739d2c06b81cf64ddf90559e",
  )
  let p3_rho = @p256.h1(p3_rho_input)
  assert_eq(
    to_hex(p3_rho.to_bytes()),
    "e10d24a8a403723bcb6f9bb4c537f316593683b472f7a89f166630dde11822c4",
  )

  // Verify H2 via complete RFC 9591 E.4 Schnorr signature verification: z * G == R + c * Y
  let sig_r_bytes = from_hex(
    "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d",
  )
  let sig_z = must_scalar(
    "9620acac6767e8e3e3036815fca4eb3a3caa69992b902bcd3352fc34f1ac192f",
  )
  let p1_sig_share = must_scalar(
    "400308eaed7a2ddee02a265abe6a1cfe04d946ee8720768899619cfabe7a3aeb",
  )
  let p3_sig_share = must_scalar(
    "561da3c179edbb0502d941bb3e3ace3c37d122aaa46fb54499f15f3a3331de44",
  )
  assert_eq(p1_sig_share.add(p3_sig_share), sig_z)

  let challenge = @p256.h2(concat_parts([sig_r_bytes, gpk_bytes, msg]))
  let r_pt = must_point(to_hex(sig_r_bytes))
  let gpk_pt = must_point(to_hex(gpk_bytes))
  assert_eq(
    @p256.P256Point::scalar_base_mul(sig_z),
    r_pt.add(gpk_pt.scalar_mul(challenge)),
  )

  // Verify H_dkg domain separation and determinism
  let dkg_c1 = @p256.h_dkg(msg)
  let dkg_c2 = @p256.h_dkg(msg)
  assert_eq(dkg_c1, dkg_c2)
  assert_false(dkg_c1.is_zero())
  assert_true(dkg_c1 != @p256.h1(msg))
  assert_true(dkg_c1 != @p256.h2(msg))
  assert_true(dkg_c1 != @p256.h3(msg))
}

///|
test "SEC1 invalid compressed point rejections" {
  // Cannot serialize identity
  assert_true(@p256.P256Point::identity().serialize_compressed() is Err(_))

  // Wrong lengths: 0, 1, 32, 34, 65
  assert_true(@p256.P256Point::deserialize_compressed(from_hex("")) is Err(_))
  assert_true(@p256.P256Point::deserialize_compressed(from_hex("00")) is Err(_))
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29600",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
      ),
    )
    is Err(_),
  )

  // Invalid prefix bytes (0x00, 0x04, 0x05) with length 33
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "000000000000000000000000000000000000000000000000000000000000000000",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "056b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      ),
    )
    is Err(_),
  )

  // x >= p (x == p and x == 0xff..ff)
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
    )
    is Err(_),
  )

  // Non-quadratic-residue x = 1 (both 0x02 and 0x03)
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "020000000000000000000000000000000000000000000000000000000000000001",
      ),
    )
    is Err(_),
  )
  assert_true(
    @p256.P256Point::deserialize_compressed(
      from_hex(
        "030000000000000000000000000000000000000000000000000000000000000001",
      ),
    )
    is Err(_),
  )
}

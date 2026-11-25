///|
fn wb_hex_nibble(c : Int32) -> Int32 {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 97 + 10
  } else if c >= 65 && c <= 70 {
    c - 65 + 10
  } else {
    abort("invalid hex char")
  }
}

///|
fn wb_hex_to_bytes(hex : String) -> Bytes {
  let n = hex.length() / 2
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = wb_hex_nibble(hex[2 * i].to_int())
    let lo = wb_hex_nibble(hex[2 * i + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn wb_bytes_to_hex(bytes : Bytes) -> String {
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
test "RFC 9496 Appendix A.4: all 6 SQRT_RATIO_M1 test vectors" {
  let vectors : Array[(String, String, Bool, String)] = [
    (
      "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000",
      true, "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
      true, "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0100000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000",
      false, "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0200000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
      false, "3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54",
    ),
    (
      "0400000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
      true, "0200000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0100000000000000000000000000000000000000000000000000000000000000", "0400000000000000000000000000000000000000000000000000000000000000",
      true, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
    ),
  ]
  assert_eq(vectors.length(), 6)
  for i = 0; i < vectors.length(); i = i + 1 {
    let (u_hex, v_hex, exp_sq, exp_r) = vectors[i]
    let u = match Fe::from_bytes_canonical(wb_hex_to_bytes(u_hex)) {
      Ok(f) => f
      Err(e) => fail("u decode failed: \{e}")
    }
    let v = match Fe::from_bytes_canonical(wb_hex_to_bytes(v_hex)) {
      Ok(f) => f
      Err(e) => fail("v decode failed: \{e}")
    }
    let (was_sq_mask, r) = Fe::sqrt_ratio_m1(u, v)
    assert_eq(was_sq_mask != 0UL, exp_sq)
    assert_eq(wb_bytes_to_hex(r.to_bytes_canonical()), exp_r)
  }
}

///|
test "Field arithmetic invariants and canonical vs unreduced decoding" {
  // Constants sanity checks
  assert_eq(fe_sqrt_m1.sq().ct_eq(Fe::minus_one()) != 0UL, true)
  assert_eq(
    fe_sqrt_ad_minus_one.sq().ct_eq(Fe::minus_one().sub(fe_d)) != 0UL,
    true,
  )
  assert_eq(
    fe_invsqrt_a_minus_d.sq().mul(Fe::minus_one().sub(fe_d)).ct_eq(Fe::one()) !=
    0UL,
    true,
  )
  assert_eq(fe_one_minus_d_sq.ct_eq(Fe::one().sub(fe_d.sq())) != 0UL, true)
  assert_eq(fe_d_minus_one_sq.ct_eq(fe_d.sub(Fe::one()).sq()) != 0UL, true)
  // ct_select / is_negative / ct_abs
  let one = Fe::one()
  let neg_one = Fe::minus_one()
  assert_eq(one.is_negative(), true)
  assert_eq(neg_one.is_negative(), false)
  assert_eq(one.ct_abs().ct_eq(neg_one) != 0UL, true)
  assert_eq(Fe::ct_select(0UL, neg_one, one).ct_eq(one) != 0UL, true)
  assert_eq(Fe::ct_select(ALL_ONES, neg_one, one).ct_eq(neg_one) != 0UL, true)
  // Canonical vs unreduced boundary around p = 2^255 - 19
  let p_bytes = wb_hex_to_bytes(
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  )
  let p_minus_1_bytes = wb_hex_to_bytes(
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  )
  let msb_set_bytes = wb_hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000080",
  )
  assert_true(Fe::from_bytes_canonical(p_bytes) is Err(_))
  assert_true(Fe::from_bytes_canonical(msb_set_bytes) is Err(_))
  match Fe::from_bytes_canonical(p_minus_1_bytes) {
    Ok(f) => assert_eq(f.ct_eq(neg_one) != 0UL, true)
    Err(e) => fail(e)
  }
  match Fe::from_bytes_unreduced(p_bytes) {
    Ok(f) => assert_eq(f.ct_eq(Fe::zero()) != 0UL, true)
    Err(e) => fail(e)
  }
  match Fe::from_bytes_unreduced(msb_set_bytes) {
    Ok(f) => assert_eq(f.ct_eq(Fe::zero()) != 0UL, true)
    Err(e) => fail(e)
  }
  // Basepoint satisfies -x^2 + y^2 == 1 + d * x^2 * y^2
  let bp = EdwardsPoint::basepoint()
  let x2 = bp.x.sq()
  let y2 = bp.y.sq()
  let lhs = y2.sub(x2)
  let rhs = Fe::one().add(fe_d.mul(x2).mul(y2))
  assert_eq(lhs.ct_eq(rhs) != 0UL, true)
  assert_eq(bp.t.ct_eq(bp.x.mul(bp.y)) != 0UL, true)
  // Doubling agrees with self-addition
  let d1 = bp.double()
  let d2 = bp.add(bp)
  assert_eq(RistrettoPoint::{ point: d1, }, RistrettoPoint::{ point: d2, })
}

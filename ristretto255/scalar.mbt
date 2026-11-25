///|
/// Constant-time Curve25519 / Ristretto255 scalar field arithmetic modulo
/// l = 2^252 + 27742317777372353535851937790883648493.
/// All Scalar values are maintained canonically in [0, l - 1] in 4x64-bit little-endian limbs.

///|
const L0 : UInt64 = 0x5812631a5cf5d3edUL

///|
const L1 : UInt64 = 0x14def9dea2f79cd6UL

///|
const L2 : UInt64 = 0x0000000000000000UL

///|
const L3 : UInt64 = 0x1000000000000000UL

///|
/// -l^(-1) mod 2^64 for Montgomery reduction with R = 2^256.
const L_INV : UInt64 = 0xd2b51da312547e1bUL

///|
/// l - 2 in 4x64-bit little-endian limbs for constant-time Fermat inversion.
const LM2_0 : UInt64 = 0x5812631a5cf5d3ebUL

///|
const LM2_1 : UInt64 = 0x14def9dea2f79cd6UL

///|
const LM2_2 : UInt64 = 0x0000000000000000UL

///|
const LM2_3 : UInt64 = 0x1000000000000000UL

///|
/// R mod l = 2^256 mod l.
const R_MOD_L_0 : UInt64 = 0xd6ec31748d98951dUL

///|
const R_MOD_L_1 : UInt64 = 0xc6ef5bf4737dcf70UL

///|
const R_MOD_L_2 : UInt64 = 0xfffffffffffffffeUL

///|
const R_MOD_L_3 : UInt64 = 0x0fffffffffffffffUL

///|
/// R^2 mod l = 2^512 mod l.
const R2_MOD_L_0 : UInt64 = 0xa40611e3449c0f01UL

///|
const R2_MOD_L_1 : UInt64 = 0xd00e1ba768859347UL

///|
const R2_MOD_L_2 : UInt64 = 0xceec73d217f5be65UL

///|
const R2_MOD_L_3 : UInt64 = 0x0399411b7c309a3dUL

///|
/// Canonical scalar in GF(l) where l is the prime order of ristretto255.
#derive(Debug)
pub struct Scalar {
  priv s0 : UInt64
  priv s1 : UInt64
  priv s2 : UInt64
  priv s3 : UInt64
}

///|
pub fn Scalar::zero() -> Scalar {
  { s0: 0UL, s1: 0UL, s2: 0UL, s3: 0UL, }
}

///|
pub fn Scalar::one() -> Scalar {
  { s0: 1UL, s1: 0UL, s2: 0UL, s3: 0UL, }
}

///|
pub fn Scalar::from_u32(n : UInt32) -> Scalar {
  { s0: n.to_uint64(), s1: 0UL, s2: 0UL, s3: 0UL, }
}

///|
/// Constant-time conditional subtraction of l from a 4-limb value < 2*l.
fn scalar_sub_l_if_ge(
  w0 : UInt64,
  w1 : UInt64,
  w2 : UInt64,
  w3 : UInt64,
) -> Scalar {
  let (d0, b0) = sub_borrow_u64(w0, L0, 0UL)
  let (d1, b1) = sub_borrow_u64(w1, L1, b0)
  let (d2, b2) = sub_borrow_u64(w2, L2, b1)
  let (d3, b3) = sub_borrow_u64(w3, L3, b2)
  // If b3 == 1 (w < l), keep w; else keep d = w - l.
  let keep_w = 0UL - b3
  {
    s0: ct_select_u64(keep_w, w0, d0),
    s1: ct_select_u64(keep_w, w1, d1),
    s2: ct_select_u64(keep_w, w2, d2),
    s3: ct_select_u64(keep_w, w3, d3),
  }
}

///|
/// Montgomery multiplication: computes a * b * 2^(-256) mod l in constant time.
/// Requires a < 2^256 and b < l (so a * b < 2^256 * l).
fn scalar_mont_mul_raw(
  a0 : UInt64,
  a1 : UInt64,
  a2 : UInt64,
  a3 : UInt64,
  b0 : UInt64,
  b1 : UInt64,
  b2 : UInt64,
  b3 : UInt64,
) -> Scalar {
  let t : FixedArray[UInt64] = FixedArray::make(8, 0UL)
  // 4x4 -> 8-limb exact product
  let (lo, c) = mul_u64_wide(a0, b0)
  t[0] = lo
  let (lo, c) = mac_u64(0UL, a0, b1, c)
  t[1] = lo
  let (lo, c) = mac_u64(0UL, a0, b2, c)
  t[2] = lo
  let (lo, c) = mac_u64(0UL, a0, b3, c)
  t[3] = lo
  t[4] = c

  let (lo, c) = mac_u64(t[1], a1, b0, 0UL)
  t[1] = lo
  let (lo, c) = mac_u64(t[2], a1, b1, c)
  t[2] = lo
  let (lo, c) = mac_u64(t[3], a1, b2, c)
  t[3] = lo
  let (lo, c) = mac_u64(t[4], a1, b3, c)
  t[4] = lo
  t[5] = c

  let (lo, c) = mac_u64(t[2], a2, b0, 0UL)
  t[2] = lo
  let (lo, c) = mac_u64(t[3], a2, b1, c)
  t[3] = lo
  let (lo, c) = mac_u64(t[4], a2, b2, c)
  t[4] = lo
  let (lo, c) = mac_u64(t[5], a2, b3, c)
  t[5] = lo
  t[6] = c

  let (lo, c) = mac_u64(t[3], a3, b0, 0UL)
  t[3] = lo
  let (lo, c) = mac_u64(t[4], a3, b1, c)
  t[4] = lo
  let (lo, c) = mac_u64(t[5], a3, b2, c)
  t[5] = lo
  let (lo, c) = mac_u64(t[6], a3, b3, c)
  t[6] = lo
  t[7] = c

  // 4-step Montgomery reduction modulo l.
  // Since t < 2^256 * l and l < 2^253, t + m * l < 2 * 2^256 * l < 2^510 < 2^512,
  // so no carry ever overflows t[7].
  for i = 0; i < 4; i = i + 1 {
    let u = t[i] * L_INV
    let (_, c0) = mac_u64(t[i], u, L0, 0UL)
    let (lo1, c1) = mac_u64(t[i + 1], u, L1, c0)
    t[i + 1] = lo1
    let (lo2, c2) = mac_u64(t[i + 2], u, L2, c1)
    t[i + 2] = lo2
    let (lo3, c3) = mac_u64(t[i + 3], u, L3, c2)
    t[i + 3] = lo3
    let mut carry = c3
    for j = i + 4; j < 8; j = j + 1 {
      let (s, c_next) = add_carry_u64(t[j], carry)
      t[j] = s
      carry = c_next
    }
  }
  scalar_sub_l_if_ge(t[4], t[5], t[6], t[7])
}

///|
fn scalar_mont_mul(a : Scalar, b : Scalar) -> Scalar {
  scalar_mont_mul_raw(a.s0, a.s1, a.s2, a.s3, b.s0, b.s1, b.s2, b.s3)
}

///|
pub fn Scalar::add(self : Scalar, other : Scalar) -> Scalar {
  // self, other < l < 2^253, so self + other < 2*l < 2^254 (no overflow out of bit 255).
  let (w0, c0) = add_carry_u64(self.s0, other.s0)
  let (w1, c1) = add_carry_in_u64(self.s1, other.s1, c0)
  let (w2, c2) = add_carry_in_u64(self.s2, other.s2, c1)
  let w3 = self.s3 + other.s3 + c2
  scalar_sub_l_if_ge(w0, w1, w2, w3)
}

///|
pub fn Scalar::sub(self : Scalar, other : Scalar) -> Scalar {
  let (d0, b0) = sub_borrow_u64(self.s0, other.s0, 0UL)
  let (d1, b1) = sub_borrow_u64(self.s1, other.s1, b0)
  let (d2, b2) = sub_borrow_u64(self.s2, other.s2, b1)
  let (d3, b3) = sub_borrow_u64(self.s3, other.s3, b2)
  let (p0, c0) = add_carry_u64(d0, L0)
  let (p1, c1) = add_carry_in_u64(d1, L1, c0)
  let (p2, c2) = add_carry_in_u64(d2, L2, c1)
  let p3 = d3 + L3 + c2
  // If b3 == 1 (self < other), select d + l; else select d.
  let add_l_mask = 0UL - b3
  {
    s0: ct_select_u64(add_l_mask, p0, d0),
    s1: ct_select_u64(add_l_mask, p1, d1),
    s2: ct_select_u64(add_l_mask, p2, d2),
    s3: ct_select_u64(add_l_mask, p3, d3),
  }
}

///|
pub fn Scalar::neg(self : Scalar) -> Scalar {
  Scalar::zero().sub(self)
}

///|
pub fn Scalar::mul(self : Scalar, other : Scalar) -> Scalar {
  let r2 : Scalar = {
    s0: R2_MOD_L_0,
    s1: R2_MOD_L_1,
    s2: R2_MOD_L_2,
    s3: R2_MOD_L_3,
  }
  let ab_mont = scalar_mont_mul(self, other)
  scalar_mont_mul(ab_mont, r2)
}

///|
/// Constant-time modular inverse via Fermat's Little Theorem: self^(l - 2) mod l.
/// Returns Err if self is zero.
pub fn Scalar::invert(self : Scalar) -> Result[Scalar, String] {
  if self.is_zero() {
    return Err("cannot invert zero scalar")
  }
  let r_mod_l : Scalar = {
    s0: R_MOD_L_0,
    s1: R_MOD_L_1,
    s2: R_MOD_L_2,
    s3: R_MOD_L_3,
  }
  let r2_mod_l : Scalar = {
    s0: R2_MOD_L_0,
    s1: R2_MOD_L_1,
    s2: R2_MOD_L_2,
    s3: R2_MOD_L_3,
  }
  // Convert to Montgomery domain: base = self * R mod l, acc = 1 * R mod l.
  let base = scalar_mont_mul(self, r2_mod_l)
  let mut acc = r_mod_l
  let exp : FixedArray[UInt64] = [LM2_0, LM2_1, LM2_2, LM2_3]
  // Exponent l - 2 is a fixed public constant; iterate bits 252 down to 0.
  for bit = 252; bit >= 0; bit = bit - 1 {
    acc = scalar_mont_mul(acc, acc)
    let limb = exp[bit >> 6]
    let is_one = ((limb >> (bit & 63)) & 1UL) == 1UL
    if is_one {
      acc = scalar_mont_mul(acc, base)
    }
  }
  // Convert out of Montgomery domain: acc * 1 * R^(-1) mod l.
  Ok(scalar_mont_mul(acc, Scalar::one()))
}

///|
pub fn Scalar::is_zero(self : Scalar) -> Bool {
  ct_is_zero_u64(self.s0 | self.s1 | self.s2 | self.s3) != 0UL
}

///|
pub fn Scalar::ct_eq(self : Scalar, other : Scalar) -> Bool {
  ct_is_zero_u64(
    (self.s0 ^ other.s0) |
    (self.s1 ^ other.s1) |
    (self.s2 ^ other.s2) |
    (self.s3 ^ other.s3),
  ) !=
  0UL
}

///|
pub impl Eq for Scalar with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// Constant-time comparison of canonical scalars as integers in [0, l - 1].
/// Returns -1 if self < other, 0 if self == other, 1 if self > other.
pub fn Scalar::compare(self : Scalar, other : Scalar) -> Int32 {
  let (_, b0) = sub_borrow_u64(self.s0, other.s0, 0UL)
  let (_, b1) = sub_borrow_u64(self.s1, other.s1, b0)
  let (_, b2) = sub_borrow_u64(self.s2, other.s2, b1)
  let (_, lt) = sub_borrow_u64(self.s3, other.s3, b2)
  let (_, g0) = sub_borrow_u64(other.s0, self.s0, 0UL)
  let (_, g1) = sub_borrow_u64(other.s1, self.s1, g0)
  let (_, g2) = sub_borrow_u64(other.s2, self.s2, g1)
  let (_, gt) = sub_borrow_u64(other.s3, self.s3, g2)
  gt.to_int() - lt.to_int()
}

///|
/// Serialize scalar as 32-byte canonical little-endian representation.
pub fn Scalar::to_bytes(self : Scalar) -> Bytes {
  let out = FixedArray::make(32, b'\x00')
  store_u64_le(out, 0, self.s0)
  store_u64_le(out, 8, self.s1)
  store_u64_le(out, 16, self.s2)
  store_u64_le(out, 24, self.s3)
  Bytes::from_array(out)
}

///|
/// Strictly deserialize 32-byte little-endian canonical scalar in [0, l - 1].
/// Rejects length != 32 or value >= l in constant time.
pub fn Scalar::from_bytes_strict(bytes : Bytes) -> Result[Scalar, String] {
  if bytes.length() != 32 {
    return Err("scalar must be 32 bytes")
  }
  let w0 = load_u64_le(bytes, 0)
  let w1 = load_u64_le(bytes, 8)
  let w2 = load_u64_le(bytes, 16)
  let w3 = load_u64_le(bytes, 24)
  let (_, b0) = sub_borrow_u64(w0, L0, 0UL)
  let (_, b1) = sub_borrow_u64(w1, L1, b0)
  let (_, b2) = sub_borrow_u64(w2, L2, b1)
  let (_, b3) = sub_borrow_u64(w3, L3, b2)
  if b3 == 0UL {
    return Err("non-canonical scalar encoding (>= l)")
  }
  Ok({ s0: w0, s1: w1, s2: w2, s3: w3, })
}

///|
/// RFC 9496 §4.4: reduce a 64-byte little-endian unsigned integer modulo l in constant time.
/// Rejects length != 64.
pub fn Scalar::from_bytes_mod_order_wide(
  bytes : Bytes,
) -> Result[Scalar, String] {
  if bytes.length() != 64 {
    return Err("wide scalar input must be 64 bytes")
  }
  let lo0 = load_u64_le(bytes, 0)
  let lo1 = load_u64_le(bytes, 8)
  let lo2 = load_u64_le(bytes, 16)
  let lo3 = load_u64_le(bytes, 24)
  let hi0 = load_u64_le(bytes, 32)
  let hi1 = load_u64_le(bytes, 40)
  let hi2 = load_u64_le(bytes, 48)
  let hi3 = load_u64_le(bytes, 56)
  // X_lo * R * R^(-1) = X_lo mod l
  let lo_part = scalar_mont_mul_raw(
    lo0,
    lo1,
    lo2,
    lo3,
    R_MOD_L_0,
    R_MOD_L_1,
    R_MOD_L_2,
    R_MOD_L_3,
  )
  // X_hi * R^2 * R^(-1) = X_hi * 2^256 mod l
  let hi_part = scalar_mont_mul_raw(
    hi0,
    hi1,
    hi2,
    hi3,
    R2_MOD_L_0,
    R2_MOD_L_1,
    R2_MOD_L_2,
    R2_MOD_L_3,
  )
  Ok(lo_part.add(hi_part))
}

///|
/// Extract the k-th 4-bit nibble (k in 0..63, LSB=0) from the canonical scalar.
/// k is a public loop index; returns a value in [0, 15].
fn Scalar::nibble(self : Scalar, k : Int32) -> UInt64 {
  let limb = match k >> 4 {
    0 => self.s0
    1 => self.s1
    2 => self.s2
    _ => self.s3
  }
  (limb >> ((k & 15) << 2)) & 0xFUL
}

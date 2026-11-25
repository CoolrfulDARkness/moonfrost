// NIST P-256 (secp256r1) scalar field F_n arithmetic in 4x64-bit Montgomery form.
// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
// All scalar operations are constant-time.

// Group order n in little-endian 64-bit limbs.

///|
const N0 : UInt64 = 0xf3b9cac2fc632551UL

///|
const N1 : UInt64 = 0xbce6faada7179e84UL

///|
const N2 : UInt64 = 0xffffffffffffffffUL

///|
const N3 : UInt64 = 0xffffffff00000000UL

// -n^(-1) mod 2^64.

///|
const N_INV : UInt64 = 0xccd1c8aaee00bc4fUL

// R mod n = 2^256 mod n (Montgomery form of 1).

///|
const N_R0 : UInt64 = 0x0c46353d039cdaafUL

///|
const N_R1 : UInt64 = 0x4319055258e8617bUL

///|
const N_R2 : UInt64 = 0x0000000000000000UL

///|
const N_R3 : UInt64 = 0x00000000ffffffffUL

// R^2 mod n = 2^512 mod n.

///|
const N_R2_0 : UInt64 = 0x83244c95be79eea2UL

///|
const N_R2_1 : UInt64 = 0x4699799c49bd6fa6UL

///|
const N_R2_2 : UInt64 = 0x2845b2392b6bec59UL

///|
const N_R2_3 : UInt64 = 0x66e12d94f3d95620UL

// 2^128 * R mod n (Montgomery form of 2^128 mod n, for 48-byte wide reduction).

///|
const N_SHIFT128_0 : UInt64 = 0xf01cf013fc632551UL

///|
const N_SHIFT128_1 : UInt64 = 0x679b73e19ad16947UL

///|
const N_SHIFT128_2 : UInt64 = 0x652e96b7ccca0a99UL

///|
const N_SHIFT128_3 : UInt64 = 0x431905529c0166ceUL

// n - 2 in little-endian 64-bit limbs (for Fermat inversion s^(n-2) mod n).

///|
const N_MINUS_2_0 : UInt64 = 0xf3b9cac2fc63254fUL

///|
const N_MINUS_2_1 : UInt64 = 0xbce6faada7179e84UL

///|
const N_MINUS_2_2 : UInt64 = 0xffffffffffffffffUL

///|
const N_MINUS_2_3 : UInt64 = 0xffffffff00000000UL

///|
#derive(Debug)
pub struct Scalar {
  priv l0 : UInt64
  priv l1 : UInt64
  priv l2 : UInt64
  priv l3 : UInt64
}

///|
pub impl Eq for Scalar with fn equal(self : Scalar, other : Scalar) -> Bool {
  self.ct_eq(other)
}

///|
pub fn Scalar::zero() -> Scalar {
  { l0: 0UL, l1: 0UL, l2: 0UL, l3: 0UL, }
}

///|
pub fn Scalar::one() -> Scalar {
  { l0: N_R0, l1: N_R1, l2: N_R2, l3: N_R3, }
}

// Montgomery reduction modulo n.

///|
fn fn_mont_reduce(
  t0 : UInt64,
  t1 : UInt64,
  t2 : UInt64,
  t3 : UInt64,
  t4 : UInt64,
  t5 : UInt64,
  t6 : UInt64,
  t7 : UInt64,
) -> Scalar {
  // Round 0
  let k = t0 * N_INV
  let (_, c) = mac(t0, k, N0, 0UL)
  let (t1, c) = mac(t1, k, N1, c)
  let (t2, c) = mac(t2, k, N2, c)
  let (t3, c) = mac(t3, k, N3, c)
  let (t4, carry2) = adc(t4, c, 0UL)

  // Round 1
  let k = t1 * N_INV
  let (_, c) = mac(t1, k, N0, 0UL)
  let (t2, c) = mac(t2, k, N1, c)
  let (t3, c) = mac(t3, k, N2, c)
  let (t4, c) = mac(t4, k, N3, c)
  let (t5, carry2) = adc(t5, c, carry2)

  // Round 2
  let k = t2 * N_INV
  let (_, c) = mac(t2, k, N0, 0UL)
  let (t3, c) = mac(t3, k, N1, c)
  let (t4, c) = mac(t4, k, N2, c)
  let (t5, c) = mac(t5, k, N3, c)
  let (t6, carry2) = adc(t6, c, carry2)

  // Round 3
  let k = t3 * N_INV
  let (_, c) = mac(t3, k, N0, 0UL)
  let (t4, c) = mac(t4, k, N1, c)
  let (t5, c) = mac(t5, k, N2, c)
  let (t6, c) = mac(t6, k, N3, c)
  let (t7, carry2) = adc(t7, c, carry2)

  // Conditional subtraction of n
  let (d0, b) = sbb(t4, N0, 0UL)
  let (d1, b) = sbb(t5, N1, b)
  let (d2, b) = sbb(t6, N2, b)
  let (d3, b) = sbb(t7, N3, b)
  let (_, underflow) = sbb(carry2, 0UL, b)
  let keep_t = 0UL - underflow
  {
    l0: ct_select_u64(keep_t, t4, d0),
    l1: ct_select_u64(keep_t, t5, d1),
    l2: ct_select_u64(keep_t, t6, d2),
    l3: ct_select_u64(keep_t, t7, d3),
  }
}

///|
fn Scalar::to_mont(
  l0 : UInt64,
  l1 : UInt64,
  l2 : UInt64,
  l3 : UInt64,
) -> Scalar {
  let raw : Scalar = { l0, l1, l2, l3, }
  let r2 : Scalar = { l0: N_R2_0, l1: N_R2_1, l2: N_R2_2, l3: N_R2_3, }
  raw.mul(r2)
}

///|
fn Scalar::from_mont(self : Scalar) -> Scalar {
  fn_mont_reduce(self.l0, self.l1, self.l2, self.l3, 0UL, 0UL, 0UL, 0UL)
}

///|
/// Converts a Montgomery-form scalar into its canonical 4x64-bit little-endian
/// limbs `(l0, l1, l2, l3)` in `[0, n - 1]` without allocating a `Bytes` buffer.
fn Scalar::to_canonical_limbs(
  self : Scalar,
) -> (UInt64, UInt64, UInt64, UInt64) {
  let canon = self.from_mont()
  (canon.l0, canon.l1, canon.l2, canon.l3)
}

///|
pub fn Scalar::from_u32(n : UInt32) -> Scalar {
  Scalar::to_mont(n.to_uint64(), 0UL, 0UL, 0UL)
}

///|
pub fn Scalar::add(self : Scalar, other : Scalar) -> Scalar {
  let (s0, c) = adc(self.l0, other.l0, 0UL)
  let (s1, c) = adc(self.l1, other.l1, c)
  let (s2, c) = adc(self.l2, other.l2, c)
  let (s3, carry) = adc(self.l3, other.l3, c)

  let (d0, b) = sbb(s0, N0, 0UL)
  let (d1, b) = sbb(s1, N1, b)
  let (d2, b) = sbb(s2, N2, b)
  let (d3, b) = sbb(s3, N3, b)
  let (_, underflow) = sbb(carry, 0UL, b)
  let keep_s = 0UL - underflow
  {
    l0: ct_select_u64(keep_s, s0, d0),
    l1: ct_select_u64(keep_s, s1, d1),
    l2: ct_select_u64(keep_s, s2, d2),
    l3: ct_select_u64(keep_s, s3, d3),
  }
}

///|
pub fn Scalar::sub(self : Scalar, other : Scalar) -> Scalar {
  let (d0, b) = sbb(self.l0, other.l0, 0UL)
  let (d1, b) = sbb(self.l1, other.l1, b)
  let (d2, b) = sbb(self.l2, other.l2, b)
  let (d3, borrow) = sbb(self.l3, other.l3, b)

  let (s0, c) = adc(d0, N0, 0UL)
  let (s1, c) = adc(d1, N1, c)
  let (s2, c) = adc(d2, N2, c)
  let (s3, _) = adc(d3, N3, c)
  let use_s = 0UL - borrow
  {
    l0: ct_select_u64(use_s, s0, d0),
    l1: ct_select_u64(use_s, s1, d1),
    l2: ct_select_u64(use_s, s2, d2),
    l3: ct_select_u64(use_s, s3, d3),
  }
}

///|
pub fn Scalar::neg(self : Scalar) -> Scalar {
  let (d0, b) = sbb(N0, self.l0, 0UL)
  let (d1, b) = sbb(N1, self.l1, b)
  let (d2, b) = sbb(N2, self.l2, b)
  let (d3, _) = sbb(N3, self.l3, b)
  let non_zero_mask = ct_is_zero_u64(self.l0 | self.l1 | self.l2 | self.l3) ^
    U64_ALL_ONES
  {
    l0: d0 & non_zero_mask,
    l1: d1 & non_zero_mask,
    l2: d2 & non_zero_mask,
    l3: d3 & non_zero_mask,
  }
}

///|
pub fn Scalar::mul(self : Scalar, other : Scalar) -> Scalar {
  let (t0, t1, t2, t3, t4, t5, t6, t7) = mul4x4(
    self.l0,
    self.l1,
    self.l2,
    self.l3,
    other.l0,
    other.l1,
    other.l2,
    other.l3,
  )
  fn_mont_reduce(t0, t1, t2, t3, t4, t5, t6, t7)
}

///|
fn Scalar::sq(self : Scalar) -> Scalar {
  self.mul(self)
}

// Constant-time multiplicative inverse via Fermat's Little Theorem: s^(n-2) mod n.
// Exponent n - 2 is a public constant, so loop control is completely independent of s.

///|
pub fn Scalar::invert(self : Scalar) -> Result[Scalar, String] {
  if self.is_zero() {
    return Err("cannot invert zero scalar")
  }
  let limbs : FixedArray[UInt64] = [
    N_MINUS_2_0,
    N_MINUS_2_1,
    N_MINUS_2_2,
    N_MINUS_2_3,
  ]
  let mut acc = Scalar::one()
  for limb_idx = 3; limb_idx >= 0; limb_idx = limb_idx - 1 {
    let w = limbs[limb_idx]
    for bit = 63; bit >= 0; bit = bit - 1 {
      acc = acc.sq()
      if ((w >> bit) & 1UL) == 1UL {
        acc = acc.mul(self)
      }
    }
  }
  Ok(acc)
}

///|
pub fn Scalar::is_zero(self : Scalar) -> Bool {
  ct_is_zero_u64(self.l0 | self.l1 | self.l2 | self.l3) != 0UL
}

///|
pub fn Scalar::ct_eq(self : Scalar, other : Scalar) -> Bool {
  ct_is_zero_u64(
    (self.l0 ^ other.l0) |
    (self.l1 ^ other.l1) |
    (self.l2 ^ other.l2) |
    (self.l3 ^ other.l3),
  ) !=
  0UL
}

// Compare two scalars as minimal non-negative integers in [0, n - 1].
// Returns -1 if self < other, 0 if self == other, 1 if self > other.

///|
pub fn Scalar::compare(self : Scalar, other : Scalar) -> Int32 {
  let a = self.from_mont()
  let b = other.from_mont()

  let (_, br1) = sbb(a.l0, b.l0, 0UL)
  let (_, br1) = sbb(a.l1, b.l1, br1)
  let (_, br1) = sbb(a.l2, b.l2, br1)
  let (_, a_lt_b) = sbb(a.l3, b.l3, br1)

  let (_, br2) = sbb(b.l0, a.l0, 0UL)
  let (_, br2) = sbb(b.l1, a.l1, br2)
  let (_, br2) = sbb(b.l2, a.l2, br2)
  let (_, b_lt_a) = sbb(b.l3, a.l3, br2)

  b_lt_a.to_int() - a_lt_b.to_int()
}

// Encode scalar as 32-byte big-endian SEC1 octet string.

///|
pub fn Scalar::to_bytes(self : Scalar) -> Bytes {
  let canon = self.from_mont()
  limbs_to_be_bytes(canon.l0, canon.l1, canon.l2, canon.l3)
}

// Strictly decode a 32-byte big-endian SEC1 scalar in [0, n - 1].

///|
pub fn Scalar::from_bytes_strict(bytes : Bytes) -> Result[Scalar, String] {
  if bytes.length() != 32 {
    return Err("p256 scalar must be 32 bytes")
  }
  let l3 = load_be_u64(bytes, 0)
  let l2 = load_be_u64(bytes, 8)
  let l1 = load_be_u64(bytes, 16)
  let l0 = load_be_u64(bytes, 24)

  // Constant-time check: (l0, l1, l2, l3) < n iff subtracting n borrows.
  let (_, b) = sbb(l0, N0, 0UL)
  let (_, b) = sbb(l1, N1, b)
  let (_, b) = sbb(l2, N2, b)
  let (_, borrow) = sbb(l3, N3, b)
  if borrow == 0UL {
    return Err("p256 scalar out of range (>= n)")
  }
  Ok(Scalar::to_mont(l0, l1, l2, l3))
}

// Reduce a 48-byte big-endian unsigned integer modulo n (RFC 9380 hash_to_field, L=48).
// Splits into three 128-bit chunks (each strictly < 2^128 < n) and evaluates via Horner's rule:
//   ((hi * 2^128 + mid) * 2^128 + lo) mod n.

///|
pub fn Scalar::from_wide_be_bytes(bytes : Bytes) -> Result[Scalar, String] {
  if bytes.length() != 48 {
    return Err("p256 wide scalar input must be 48 bytes")
  }
  let hi_l1 = load_be_u64(bytes, 0)
  let hi_l0 = load_be_u64(bytes, 8)
  let mid_l1 = load_be_u64(bytes, 16)
  let mid_l0 = load_be_u64(bytes, 24)
  let lo_l1 = load_be_u64(bytes, 32)
  let lo_l0 = load_be_u64(bytes, 40)

  let s_hi = Scalar::to_mont(hi_l0, hi_l1, 0UL, 0UL)
  let s_mid = Scalar::to_mont(mid_l0, mid_l1, 0UL, 0UL)
  let s_lo = Scalar::to_mont(lo_l0, lo_l1, 0UL, 0UL)
  let shift128 : Scalar = {
    l0: N_SHIFT128_0,
    l1: N_SHIFT128_1,
    l2: N_SHIFT128_2,
    l3: N_SHIFT128_3,
  }
  Ok(s_hi.mul(shift128).add(s_mid).mul(shift128).add(s_lo))
}

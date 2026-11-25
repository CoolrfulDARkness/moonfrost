// NIST P-256 (secp256r1) prime field F_p arithmetic in 4x64-bit Montgomery form.
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
// All field operations are constant-time (branchless arithmetic, no secret-dependent branches).

///|
const U64_ALL_ONES : UInt64 = 0xffffffffffffffffUL

// P-256 prime p in little-endian 64-bit limbs.

///|
const P0 : UInt64 = 0xffffffffffffffffUL

///|
const P1 : UInt64 = 0x00000000ffffffffUL

///|
const P2 : UInt64 = 0x0000000000000000UL

///|
const P3 : UInt64 = 0xffffffff00000001UL

// R mod p = 2^256 mod p (Montgomery form of 1).

///|
const P_R0 : UInt64 = 0x0000000000000001UL

///|
const P_R1 : UInt64 = 0xffffffff00000000UL

///|
const P_R2 : UInt64 = 0xffffffffffffffffUL

///|
const P_R3 : UInt64 = 0x00000000fffffffeUL

// R^2 mod p = 2^512 mod p (for converting into Montgomery form).

///|
const P_R2_0 : UInt64 = 0x0000000000000003UL

///|
const P_R2_1 : UInt64 = 0xfffffffbffffffffUL

///|
const P_R2_2 : UInt64 = 0xfffffffffffffffeUL

///|
const P_R2_3 : UInt64 = 0x00000004fffffffdUL

// Constant-time helper primitives (internal to p256 package).

///|
fn ct_is_zero_u64(x : UInt64) -> UInt64 {
  let neg_x = 0UL - x
  let nz = (x | neg_x) >> 63
  nz - 1UL
}

///|
fn ct_eq_u64(a : UInt64, b : UInt64) -> UInt64 {
  ct_is_zero_u64(a ^ b)
}

///|
fn ct_mask_from_bit(bit : UInt64) -> UInt64 {
  0UL - (bit & 1UL)
}

///|
fn ct_select_u64(mask : UInt64, a : UInt64, b : UInt64) -> UInt64 {
  (a & mask) | (b & (mask ^ U64_ALL_ONES))
}

// Branchless 64-bit add with carry (carry in {0, 1}).

///|
fn adc(a : UInt64, b : UInt64, carry : UInt64) -> (UInt64, UInt64) {
  let s1 = a + b
  let c1 = ((a & b) | ((a | b) & (s1 ^ U64_ALL_ONES))) >> 63
  let s2 = s1 + carry
  let c2 = ((s1 & carry) | ((s1 | carry) & (s2 ^ U64_ALL_ONES))) >> 63
  (s2, c1 | c2)
}

// Branchless 64-bit subtract with borrow (borrow in {0, 1}).

///|
fn sbb(a : UInt64, b : UInt64, borrow : UInt64) -> (UInt64, UInt64) {
  let d1 = a - b
  let na = a ^ U64_ALL_ONES
  let b1 = ((na & b) | ((na ^ b) & d1)) >> 63
  let d2 = d1 - borrow
  let nd1 = d1 ^ U64_ALL_ONES
  let b2 = ((nd1 & borrow) | ((nd1 ^ borrow) & d2)) >> 63
  (d2, b1 | b2)
}

// Branchless 64x64 -> 128-bit unsigned multiplication returning (lo, hi).

///|
fn mul64(a : UInt64, b : UInt64) -> (UInt64, UInt64) {
  let mask : UInt64 = 0xffffffffUL
  let a0 = a & mask
  let a1 = a >> 32
  let b0 = b & mask
  let b1 = b >> 32
  let p00 = a0 * b0
  let p01 = a0 * b1
  let p10 = a1 * b0
  let p11 = a1 * b1
  let mid = (p00 >> 32) + (p01 & mask) + (p10 & mask)
  let lo = (p00 & mask) | (mid << 32)
  let hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32)
  (lo, hi)
}

// Branchless multiply-accumulate: acc + a * b + carry -> (lo, hi).
// Max value = (2^64-1) + (2^64-1)^2 + (2^64-1) = 2^128 - 1 (no overflow).

///|
fn mac(
  acc : UInt64,
  a : UInt64,
  b : UInt64,
  carry : UInt64,
) -> (UInt64, UInt64) {
  let (lo, hi) = mul64(a, b)
  let (s1, c1) = adc(acc, lo, 0UL)
  let (s2, c2) = adc(s1, carry, 0UL)
  (s2, hi + c1 + c2)
}

// 4-limb x 4-limb schoolbook product -> 8-limb little-endian product.

///|
fn mul4x4(
  a0 : UInt64,
  a1 : UInt64,
  a2 : UInt64,
  a3 : UInt64,
  b0 : UInt64,
  b1 : UInt64,
  b2 : UInt64,
  b3 : UInt64,
) -> (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) {
  let (r0, c) = mac(0UL, a0, b0, 0UL)
  let (r1, c) = mac(0UL, a0, b1, c)
  let (r2, c) = mac(0UL, a0, b2, c)
  let (r3, r4) = mac(0UL, a0, b3, c)

  let (r1, c) = mac(r1, a1, b0, 0UL)
  let (r2, c) = mac(r2, a1, b1, c)
  let (r3, c) = mac(r3, a1, b2, c)
  let (r4, r5) = mac(r4, a1, b3, c)

  let (r2, c) = mac(r2, a2, b0, 0UL)
  let (r3, c) = mac(r3, a2, b1, c)
  let (r4, c) = mac(r4, a2, b2, c)
  let (r5, r6) = mac(r5, a2, b3, c)

  let (r3, c) = mac(r3, a3, b0, 0UL)
  let (r4, c) = mac(r4, a3, b1, c)
  let (r5, c) = mac(r5, a3, b2, c)
  let (r6, r7) = mac(r6, a3, b3, c)

  (r0, r1, r2, r3, r4, r5, r6, r7)
}

// Load 8 big-endian bytes starting at offset into a UInt64.

///|
fn load_be_u64(bytes : Bytes, offset : Int32) -> UInt64 {
  (bytes[offset].to_uint64() << 56) |
  (bytes[offset + 1].to_uint64() << 48) |
  (bytes[offset + 2].to_uint64() << 40) |
  (bytes[offset + 3].to_uint64() << 32) |
  (bytes[offset + 4].to_uint64() << 24) |
  (bytes[offset + 5].to_uint64() << 16) |
  (bytes[offset + 6].to_uint64() << 8) |
  bytes[offset + 7].to_uint64()
}

// Store 4 little-endian limbs as 32 big-endian bytes.

///|
fn limbs_to_be_bytes(
  l0 : UInt64,
  l1 : UInt64,
  l2 : UInt64,
  l3 : UInt64,
) -> Bytes {
  Bytes::makei(32, fn(i) {
    let limb = if i < 8 {
      l3
    } else if i < 16 {
      l2
    } else if i < 24 {
      l1
    } else {
      l0
    }
    let shift = (7 - (i & 7)) * 8
    ((limb >> shift) & 0xffUL).to_byte()
  })
}

// NIST P-256 prime field element stored in Montgomery form (a * 2^256 mod p).

///|
#derive(Debug)
pub struct FieldElement {
  priv l0 : UInt64
  priv l1 : UInt64
  priv l2 : UInt64
  priv l3 : UInt64
}

///|
pub impl Eq for FieldElement with fn equal(
  self : FieldElement,
  other : FieldElement,
) -> Bool {
  self.ct_eq(other)
}

///|
fn FieldElement::from_raw_mont(
  l0 : UInt64,
  l1 : UInt64,
  l2 : UInt64,
  l3 : UInt64,
) -> FieldElement {
  { l0, l1, l2, l3, }
}

///|
pub fn FieldElement::zero() -> FieldElement {
  { l0: 0UL, l1: 0UL, l2: 0UL, l3: 0UL, }
}

///|
pub fn FieldElement::one() -> FieldElement {
  { l0: P_R0, l1: P_R1, l2: P_R2, l3: P_R3, }
}

// Montgomery reduction modulo p (p' = -p^-1 mod 2^64 = 1).

///|
fn fp_mont_reduce(
  t0 : UInt64,
  t1 : UInt64,
  t2 : UInt64,
  t3 : UInt64,
  t4 : UInt64,
  t5 : UInt64,
  t6 : UInt64,
  t7 : UInt64,
) -> FieldElement {
  // Round 0: k = t0 * 1 = t0
  let k = t0
  let (_, c) = mac(t0, k, P0, 0UL)
  let (t1, c) = mac(t1, k, P1, c)
  let (t2, c) = mac(t2, k, P2, c)
  let (t3, c) = mac(t3, k, P3, c)
  let (t4, carry2) = adc(t4, c, 0UL)

  // Round 1: k = t1
  let k = t1
  let (_, c) = mac(t1, k, P0, 0UL)
  let (t2, c) = mac(t2, k, P1, c)
  let (t3, c) = mac(t3, k, P2, c)
  let (t4, c) = mac(t4, k, P3, c)
  let (t5, carry2) = adc(t5, c, carry2)

  // Round 2: k = t2
  let k = t2
  let (_, c) = mac(t2, k, P0, 0UL)
  let (t3, c) = mac(t3, k, P1, c)
  let (t4, c) = mac(t4, k, P2, c)
  let (t5, c) = mac(t5, k, P3, c)
  let (t6, carry2) = adc(t6, c, carry2)

  // Round 3: k = t3
  let k = t3
  let (_, c) = mac(t3, k, P0, 0UL)
  let (t4, c) = mac(t4, k, P1, c)
  let (t5, c) = mac(t5, k, P2, c)
  let (t6, c) = mac(t6, k, P3, c)
  let (t7, carry2) = adc(t7, c, carry2)

  // Conditional subtraction of p (result in [0, 2p - 1] -> [0, p - 1])
  let (d0, b) = sbb(t4, P0, 0UL)
  let (d1, b) = sbb(t5, P1, b)
  let (d2, b) = sbb(t6, P2, b)
  let (d3, b) = sbb(t7, P3, b)
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
pub fn FieldElement::add(
  self : FieldElement,
  other : FieldElement,
) -> FieldElement {
  let (s0, c) = adc(self.l0, other.l0, 0UL)
  let (s1, c) = adc(self.l1, other.l1, c)
  let (s2, c) = adc(self.l2, other.l2, c)
  let (s3, carry) = adc(self.l3, other.l3, c)

  let (d0, b) = sbb(s0, P0, 0UL)
  let (d1, b) = sbb(s1, P1, b)
  let (d2, b) = sbb(s2, P2, b)
  let (d3, b) = sbb(s3, P3, b)
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
pub fn FieldElement::sub(
  self : FieldElement,
  other : FieldElement,
) -> FieldElement {
  let (d0, b) = sbb(self.l0, other.l0, 0UL)
  let (d1, b) = sbb(self.l1, other.l1, b)
  let (d2, b) = sbb(self.l2, other.l2, b)
  let (d3, borrow) = sbb(self.l3, other.l3, b)

  let (s0, c) = adc(d0, P0, 0UL)
  let (s1, c) = adc(d1, P1, c)
  let (s2, c) = adc(d2, P2, c)
  let (s3, _) = adc(d3, P3, c)
  let use_s = 0UL - borrow
  {
    l0: ct_select_u64(use_s, s0, d0),
    l1: ct_select_u64(use_s, s1, d1),
    l2: ct_select_u64(use_s, s2, d2),
    l3: ct_select_u64(use_s, s3, d3),
  }
}

///|
pub fn FieldElement::neg(self : FieldElement) -> FieldElement {
  let (d0, b) = sbb(P0, self.l0, 0UL)
  let (d1, b) = sbb(P1, self.l1, b)
  let (d2, b) = sbb(P2, self.l2, b)
  let (d3, _) = sbb(P3, self.l3, b)
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
pub fn FieldElement::mul(
  self : FieldElement,
  other : FieldElement,
) -> FieldElement {
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
  fp_mont_reduce(t0, t1, t2, t3, t4, t5, t6, t7)
}

///|
pub fn FieldElement::sq(self : FieldElement) -> FieldElement {
  self.mul(self)
}

///|
fn FieldElement::sq_n(self : FieldElement, n : Int32) -> FieldElement {
  let mut acc = self
  for i = 0; i < n; i = i + 1 {
    acc = acc.sq()
  }
  acc
}

// Constant-time multiplicative inverse via Fermat's Little Theorem: a^(p-2) mod p.
// Returns 0 for 0.
// p - 2 = ((2^32 - 1) << 224) + (1 << 192) + ((2^94 - 1) << 2) + 1

///|
pub fn FieldElement::inv(self : FieldElement) -> FieldElement {
  let x2 = self.sq().mul(self) // 2^2 - 1
  let x3 = x2.sq().mul(self) // 2^3 - 1
  let x6 = x3.sq_n(3).mul(x3) // 2^6 - 1
  let x12 = x6.sq_n(6).mul(x6) // 2^12 - 1
  let x15 = x12.sq_n(3).mul(x3) // 2^15 - 1
  let x30 = x15.sq_n(15).mul(x15) // 2^30 - 1
  let x32 = x30.sq_n(2).mul(x2) // 2^32 - 1

  let mut t = x32.sq_n(32).mul(self)
  t = t.sq_n(96)
  t = t.sq_n(32).mul(x32)
  t = t.sq_n(32).mul(x32)
  t = t.sq_n(30).mul(x30)
  t.sq_n(2).mul(self)
}

// Constant-time square root modulo p (p = 3 mod 4):
// Computes candidate r = a^((p + 1) / 4) mod p and verifies r^2 == a.
// (p + 1) / 4 = ((2^32 - 1) << 222) + (1 << 190) + (1 << 94)

///|
pub fn FieldElement::sqrt(self : FieldElement) -> FieldElement? {
  let x2 = self.sq().mul(self) // 2^2 - 1
  let x3 = x2.sq().mul(self) // 2^3 - 1
  let x6 = x3.sq_n(3).mul(x3) // 2^6 - 1
  let x12 = x6.sq_n(6).mul(x6) // 2^12 - 1
  let x15 = x12.sq_n(3).mul(x3) // 2^15 - 1
  let x30 = x15.sq_n(15).mul(x15) // 2^30 - 1
  let x32 = x30.sq_n(2).mul(x2) // 2^32 - 1

  let t = x32.sq_n(32).mul(self).sq_n(96).mul(self).sq_n(94)
  if t.sq().ct_eq(self) {
    Some(t)
  } else {
    None
  }
}

///|
fn FieldElement::from_mont(self : FieldElement) -> FieldElement {
  fp_mont_reduce(self.l0, self.l1, self.l2, self.l3, 0UL, 0UL, 0UL, 0UL)
}

///|
fn FieldElement::ct_is_zero_mask(self : FieldElement) -> UInt64 {
  ct_is_zero_u64(self.l0 | self.l1 | self.l2 | self.l3)
}

///|
fn FieldElement::ct_eq_mask(
  self : FieldElement,
  other : FieldElement,
) -> UInt64 {
  ct_is_zero_u64(
    (self.l0 ^ other.l0) |
    (self.l1 ^ other.l1) |
    (self.l2 ^ other.l2) |
    (self.l3 ^ other.l3),
  )
}

///|
pub fn FieldElement::is_zero(self : FieldElement) -> Bool {
  self.ct_is_zero_mask() != 0UL
}

///|
pub fn FieldElement::ct_eq(self : FieldElement, other : FieldElement) -> Bool {
  self.ct_eq_mask(other) != 0UL
}

///|
pub fn FieldElement::ct_select(
  mask : UInt64,
  a : FieldElement,
  b : FieldElement,
) -> FieldElement {
  {
    l0: ct_select_u64(mask, a.l0, b.l0),
    l1: ct_select_u64(mask, a.l1, b.l1),
    l2: ct_select_u64(mask, a.l2, b.l2),
    l3: ct_select_u64(mask, a.l3, b.l3),
  }
}

///|
fn FieldElement::is_odd_bit(self : FieldElement) -> UInt64 {
  let canon = self.from_mont()
  canon.l0 & 1UL
}

///|
pub fn FieldElement::is_odd(self : FieldElement) -> Bool {
  self.is_odd_bit() != 0UL
}

// Strictly decode a 32-byte big-endian field element (< p).

///|
pub fn FieldElement::from_bytes_be_strict(
  bytes : Bytes,
) -> Result[FieldElement, String] {
  if bytes.length() != 32 {
    return Err("p256 field element must be 32 bytes")
  }
  let l3 = load_be_u64(bytes, 0)
  let l2 = load_be_u64(bytes, 8)
  let l1 = load_be_u64(bytes, 16)
  let l0 = load_be_u64(bytes, 24)

  // Constant-time check: (l0, l1, l2, l3) < p iff subtracting p borrows.
  let (_, b) = sbb(l0, P0, 0UL)
  let (_, b) = sbb(l1, P1, b)
  let (_, b) = sbb(l2, P2, b)
  let (_, borrow) = sbb(l3, P3, b)
  if borrow == 0UL {
    return Err("p256 field element out of range (>= p)")
  }
  let raw : FieldElement = { l0, l1, l2, l3, }
  let r2 : FieldElement = { l0: P_R2_0, l1: P_R2_1, l2: P_R2_2, l3: P_R2_3, }
  Ok(raw.mul(r2))
}

// Encode a field element as 32 big-endian bytes.

///|
pub fn FieldElement::to_bytes_be(self : FieldElement) -> Bytes {
  let canon = self.from_mont()
  limbs_to_be_bytes(canon.l0, canon.l1, canon.l2, canon.l3)
}

///|
/// Constant-time GF(2^255 - 19) field arithmetic using 5x51-bit UInt64 limbs.
/// Invariant for all normalized/operation-output Fe values:
///   l0, l2, l3, l4 < 2^51 and l1 <= 2^51 (so every limb < 2^52).

///|
const MASK51 : UInt64 = 0x7FFFFFFFFFFFFUL

///|
const MASK32 : UInt64 = 0xFFFFFFFFUL

///|
const ALL_ONES : UInt64 = 0xFFFFFFFFFFFFFFFFUL

///|
/// 4 * p in 5x51-bit limbs for underflow-free subtraction when limbs < 2^52.
const P4_0 : UInt64 = 0x1FFFFFFFFFFFB4UL

///|
const P4_1234 : UInt64 = 0x1FFFFFFFFFFFFCUL

///|
/// Canonical modulus p = 2^255 - 19 in 4x64-bit little-endian words.
const P_W0 : UInt64 = 0xFFFFFFFFFFFFFFEDUL

///|
const P_W1 : UInt64 = 0xFFFFFFFFFFFFFFFFUL

///|
const P_W2 : UInt64 = 0xFFFFFFFFFFFFFFFFUL

///|
const P_W3 : UInt64 = 0x7FFFFFFFFFFFFFFFUL

///|
#derive(Debug)
priv struct Fe {
  l0 : UInt64
  l1 : UInt64
  l2 : UInt64
  l3 : UInt64
  l4 : UInt64
}

///|
priv struct U128 {
  lo : UInt64
  hi : UInt64
}

///|
/// Branchless unsigned 64-bit addition returning (sum, carry in {0, 1}).
fn add_carry_u64(a : UInt64, b : UInt64) -> (UInt64, UInt64) {
  let s = a + b
  let c = ((a & b) | ((a | b) & (s ^ ALL_ONES))) >> 63
  (s, c)
}

///|
/// Branchless unsigned 64-bit addition with carry-in in {0, 1}.
fn add_carry_in_u64(
  a : UInt64,
  b : UInt64,
  carry_in : UInt64,
) -> (UInt64, UInt64) {
  let (s1, c1) = add_carry_u64(a, b)
  let (s2, c2) = add_carry_u64(s1, carry_in)
  (s2, c1 | c2)
}

///|
/// Branchless unsigned 64-bit subtraction with borrow-in in {0, 1}.
fn sub_borrow_u64(
  a : UInt64,
  b : UInt64,
  borrow_in : UInt64,
) -> (UInt64, UInt64) {
  let d1 = a - b
  let b1 = (((a ^ ALL_ONES) & b) | ((a ^ b ^ ALL_ONES) & d1)) >> 63
  let d2 = d1 - borrow_in
  let b2 = (((d1 ^ ALL_ONES) & borrow_in) | ((d1 ^ borrow_in ^ ALL_ONES) & d2)) >>
    63
  (d2, b1 | b2)
}

///|
/// Exact 64x64 -> 128-bit unsigned multiplication.
fn mul_u64_wide(a : UInt64, b : UInt64) -> (UInt64, UInt64) {
  let a0 = a & MASK32
  let a1 = a >> 32
  let b0 = b & MASK32
  let b1 = b >> 32
  let p00 = a0 * b0
  let p01 = a0 * b1
  let p10 = a1 * b0
  let p11 = a1 * b1
  let mid = (p00 >> 32) + (p01 & MASK32) + (p10 & MASK32)
  let lo = (p00 & MASK32) | (mid << 32)
  let hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32)
  (lo, hi)
}

///|
/// Multiply-accumulate: acc + a * b + carry -> (lo, hi).
fn mac_u64(
  acc : UInt64,
  a : UInt64,
  b : UInt64,
  carry : UInt64,
) -> (UInt64, UInt64) {
  let (p_lo, p_hi) = mul_u64_wide(a, b)
  let (s1, c1) = add_carry_u64(p_lo, acc)
  let (lo, c2) = add_carry_u64(s1, carry)
  let hi = p_hi + c1 + c2
  (lo, hi)
}

///|
fn u128_mul(a : UInt64, b : UInt64) -> U128 {
  let (lo, hi) = mul_u64_wide(a, b)
  { lo, hi, }
}

///|
fn U128::add(self : U128, other : U128) -> U128 {
  let (lo, c) = add_carry_u64(self.lo, other.lo)
  { lo, hi: self.hi + other.hi + c, }
}

///|
fn U128::add_u64(self : U128, x : UInt64) -> U128 {
  let (lo, c) = add_carry_u64(self.lo, x)
  { lo, hi: self.hi + c, }
}

///|
/// Right shift a 128-bit value by 51 bits, returning a UInt64 (valid when value < 2^115).
fn U128::shr51_u64(self : U128) -> UInt64 {
  (self.lo >> 51) | (self.hi << 13)
}

///|
/// Constant-time mask: returns ALL_ONES if x == 0, else 0.
fn ct_is_zero_u64(x : UInt64) -> UInt64 {
  let nz = (x | (0UL - x)) >> 63
  0UL - (nz ^ 1UL)
}

///|
/// Constant-time mask: returns ALL_ONES if a == b, else 0.
fn ct_eq_u64_mask(a : UInt64, b : UInt64) -> UInt64 {
  ct_is_zero_u64(a ^ b)
}

///|
/// Constant-time select: returns if_true when mask == ALL_ONES, else if_false.
fn ct_select_u64(mask : UInt64, if_true : UInt64, if_false : UInt64) -> UInt64 {
  if_false ^ (mask & (if_false ^ if_true))
}

///|
/// Constant-time select for Fe: returns if_true when mask == ALL_ONES, else if_false.
/// Matches RFC 9496 CT_SELECT(v IF cond ELSE u) argument order.
fn Fe::ct_select(mask : UInt64, if_true : Fe, if_false : Fe) -> Fe {
  {
    l0: ct_select_u64(mask, if_true.l0, if_false.l0),
    l1: ct_select_u64(mask, if_true.l1, if_false.l1),
    l2: ct_select_u64(mask, if_true.l2, if_false.l2),
    l3: ct_select_u64(mask, if_true.l3, if_false.l3),
    l4: ct_select_u64(mask, if_true.l4, if_false.l4),
  }
}

///|
/// Load 8 bytes starting at offset as little-endian UInt64.
fn load_u64_le(bytes : Bytes, offset : Int32) -> UInt64 {
  bytes[offset].to_uint64() |
  (bytes[offset + 1].to_uint64() << 8) |
  (bytes[offset + 2].to_uint64() << 16) |
  (bytes[offset + 3].to_uint64() << 24) |
  (bytes[offset + 4].to_uint64() << 32) |
  (bytes[offset + 5].to_uint64() << 40) |
  (bytes[offset + 6].to_uint64() << 48) |
  (bytes[offset + 7].to_uint64() << 56)
}

///|
/// Store UInt64 into a FixedArray[Byte] at offset in little-endian order.
fn store_u64_le(out : FixedArray[Byte], offset : Int32, v : UInt64) -> Unit {
  out[offset] = (v & 0xFFUL).to_byte()
  out[offset + 1] = ((v >> 8) & 0xFFUL).to_byte()
  out[offset + 2] = ((v >> 16) & 0xFFUL).to_byte()
  out[offset + 3] = ((v >> 24) & 0xFFUL).to_byte()
  out[offset + 4] = ((v >> 32) & 0xFFUL).to_byte()
  out[offset + 5] = ((v >> 40) & 0xFFUL).to_byte()
  out[offset + 6] = ((v >> 48) & 0xFFUL).to_byte()
  out[offset + 7] = ((v >> 56) & 0xFFUL).to_byte()
}

///|
fn Fe::zero() -> Fe {
  { l0: 0UL, l1: 0UL, l2: 0UL, l3: 0UL, l4: 0UL, }
}

///|
fn Fe::one() -> Fe {
  { l0: 1UL, l1: 0UL, l2: 0UL, l3: 0UL, l4: 0UL, }
}

///|
fn Fe::minus_one() -> Fe {
  Fe::zero().sub(Fe::one())
}

///|
/// RFC 9496 §4.1 implementation constants.
let fe_d : Fe = {
  l0: 0x34dca135978a3UL,
  l1: 0x1a8283b156ebdUL,
  l2: 0x5e7a26001c029UL,
  l3: 0x739c663a03cbbUL,
  l4: 0x52036cee2b6ffUL,
}

///|
let fe_two_d : Fe = {
  l0: 0x69b9426b2f159UL,
  l1: 0x35050762add7aUL,
  l2: 0x3cf44c0038052UL,
  l3: 0x6738cc7407977UL,
  l4: 0x2406d9dc56dffUL,
}

///|
let fe_sqrt_m1 : Fe = {
  l0: 0x61b274a0ea0b0UL,
  l1: 0x0d5a5fc8f189dUL,
  l2: 0x7ef5e9cbd0c60UL,
  l3: 0x78595a6804c9eUL,
  l4: 0x2b8324804fc1dUL,
}

///|
let fe_sqrt_ad_minus_one : Fe = {
  l0: 0x7f6a0497b2e1bUL,
  l1: 0x1836f0a97afd2UL,
  l2: 0x7d747f6be7638UL,
  l3: 0x456079e7e6498UL,
  l4: 0x376931bf2b834UL,
}

///|
let fe_invsqrt_a_minus_d : Fe = {
  l0: 0x0fdaa805d40eaUL,
  l1: 0x2eb482e57d339UL,
  l2: 0x007610274bc58UL,
  l3: 0x6510b613dc8ffUL,
  l4: 0x786c8905cfaffUL,
}

///|
let fe_one_minus_d_sq : Fe = {
  l0: 0x409c1945fc176UL,
  l1: 0x719abc6a1fc4fUL,
  l2: 0x1c37f90b20684UL,
  l3: 0x06bccca55eedfUL,
  l4: 0x029072a8b2b3eUL,
}

///|
let fe_d_minus_one_sq : Fe = {
  l0: 0x55aaa44ed4d20UL,
  l1: 0x59603c3332635UL,
  l2: 0x26d3baf4a7928UL,
  l3: 0x120a66e6997a9UL,
  l4: 0x5968b37af66c2UL,
}

///|
/// Weak carry reduction keeping l0, l2, l3, l4 < 2^51 and l1 <= 2^51 (for inputs < 2^55).
fn fe_reduce_weak(
  d0 : UInt64,
  d1 : UInt64,
  d2 : UInt64,
  d3 : UInt64,
  d4 : UInt64,
) -> Fe {
  let c0 = d0 >> 51
  let r0 = d0 & MASK51
  let d1 = d1 + c0
  let c1 = d1 >> 51
  let r1 = d1 & MASK51
  let d2 = d2 + c1
  let c2 = d2 >> 51
  let r2 = d2 & MASK51
  let d3 = d3 + c2
  let c3 = d3 >> 51
  let r3 = d3 & MASK51
  let d4 = d4 + c3
  let c4 = d4 >> 51
  let r4 = d4 & MASK51
  let r0 = r0 + c4 * 19UL
  let c0b = r0 >> 51
  let r0 = r0 & MASK51
  let r1 = r1 + c0b
  { l0: r0, l1: r1, l2: r2, l3: r3, l4: r4, }
}

///|
/// Full canonical reduction mod p = 2^255 - 19 into unique [0, p - 1].
fn Fe::canonicalize(self : Fe) -> Fe {
  // Pass 1: weak carry
  let w = fe_reduce_weak(self.l0, self.l1, self.l2, self.l3, self.l4)
  // Pass 2: clear any carry from l1 == 2^51 so all limbs are strictly < 2^51 (< 2^255 total)
  let c1 = w.l1 >> 51
  let r1 = w.l1 & MASK51
  let t2 = w.l2 + c1
  let c2 = t2 >> 51
  let r2 = t2 & MASK51
  let t3 = w.l3 + c2
  let c3 = t3 >> 51
  let r3 = t3 & MASK51
  let t4 = w.l4 + c3
  let c4 = t4 >> 51
  let r4 = t4 & MASK51
  let r0 = w.l0 + c4 * 19UL
  // Now val < 2^255 = p + 19. Compute q = (val + 19) >> 255 in {0, 1}.
  let mut q = (r0 + 19UL) >> 51
  q = (r1 + q) >> 51
  q = (r2 + q) >> 51
  q = (r3 + q) >> 51
  q = (r4 + q) >> 51
  // Conditionally subtract p = 2^255 - 19 by adding 19*q and masking top bit at 2^255.
  let s0 = r0 + 19UL * q
  let s1 = r1 + (s0 >> 51)
  let f0 = s0 & MASK51
  let s2 = r2 + (s1 >> 51)
  let f1 = s1 & MASK51
  let s3 = r3 + (s2 >> 51)
  let f2 = s2 & MASK51
  let s4 = r4 + (s3 >> 51)
  let f3 = s3 & MASK51
  let f4 = s4 & MASK51
  { l0: f0, l1: f1, l2: f2, l3: f3, l4: f4, }
}

///|
fn Fe::add(self : Fe, other : Fe) -> Fe {
  fe_reduce_weak(
    self.l0 + other.l0,
    self.l1 + other.l1,
    self.l2 + other.l2,
    self.l3 + other.l3,
    self.l4 + other.l4,
  )
}

///|
fn Fe::sub(self : Fe, other : Fe) -> Fe {
  fe_reduce_weak(
    self.l0 + P4_0 - other.l0,
    self.l1 + P4_1234 - other.l1,
    self.l2 + P4_1234 - other.l2,
    self.l3 + P4_1234 - other.l3,
    self.l4 + P4_1234 - other.l4,
  )
}

///|
fn Fe::neg(self : Fe) -> Fe {
  fe_reduce_weak(
    P4_0 - self.l0,
    P4_1234 - self.l1,
    P4_1234 - self.l2,
    P4_1234 - self.l3,
    P4_1234 - self.l4,
  )
}

///|
fn Fe::mul(self : Fe, other : Fe) -> Fe {
  let a0 = self.l0
  let a1 = self.l1
  let a2 = self.l2
  let a3 = self.l3
  let a4 = self.l4
  let b0 = other.l0
  let b1 = other.l1
  let b2 = other.l2
  let b3 = other.l3
  let b4 = other.l4
  let b1_19 = b1 * 19UL
  let b2_19 = b2 * 19UL
  let b3_19 = b3 * 19UL
  let b4_19 = b4 * 19UL
  let c0 = u128_mul(a0, b0)
    .add(u128_mul(a1, b4_19))
    .add(u128_mul(a2, b3_19))
    .add(u128_mul(a3, b2_19))
    .add(u128_mul(a4, b1_19))
  let c1 = u128_mul(a0, b1)
    .add(u128_mul(a1, b0))
    .add(u128_mul(a2, b4_19))
    .add(u128_mul(a3, b3_19))
    .add(u128_mul(a4, b2_19))
  let c2 = u128_mul(a0, b2)
    .add(u128_mul(a1, b1))
    .add(u128_mul(a2, b0))
    .add(u128_mul(a3, b4_19))
    .add(u128_mul(a4, b3_19))
  let c3 = u128_mul(a0, b3)
    .add(u128_mul(a1, b2))
    .add(u128_mul(a2, b1))
    .add(u128_mul(a3, b0))
    .add(u128_mul(a4, b4_19))
  let c4 = u128_mul(a0, b4)
    .add(u128_mul(a1, b3))
    .add(u128_mul(a2, b2))
    .add(u128_mul(a3, b1))
    .add(u128_mul(a4, b0))
  let r0 = c0.lo & MASK51
  let c1 = c1.add_u64(c0.shr51_u64())
  let r1 = c1.lo & MASK51
  let c2 = c2.add_u64(c1.shr51_u64())
  let r2 = c2.lo & MASK51
  let c3 = c3.add_u64(c2.shr51_u64())
  let r3 = c3.lo & MASK51
  let c4 = c4.add_u64(c3.shr51_u64())
  let r4 = c4.lo & MASK51
  let carry = c4.shr51_u64()
  let r0 = r0 + carry * 19UL
  let r1 = r1 + (r0 >> 51)
  let r0 = r0 & MASK51
  let r2 = r2 + (r1 >> 51)
  let r1 = r1 & MASK51
  // Normalize r2 carry if any (at most 1)
  let r3 = r3 + (r2 >> 51)
  let r2 = r2 & MASK51
  let r4 = r4 + (r3 >> 51)
  let r3 = r3 & MASK51
  let r0 = r0 + (r4 >> 51) * 19UL
  let r4 = r4 & MASK51
  let r1 = r1 + (r0 >> 51)
  let r0 = r0 & MASK51
  { l0: r0, l1: r1, l2: r2, l3: r3, l4: r4, }
}

///|
fn Fe::sq(self : Fe) -> Fe {
  self.mul(self)
}

///|
fn Fe::sq_k(self : Fe, k : Int32) -> Fe {
  let mut r = self
  for _i = 0; _i < k; _i = _i + 1 {
    r = r.sq()
  }
  r
}

///|
/// Compute self^((p - 5) / 8) = self^(2^252 - 3) via fixed addition chain.
fn Fe::pow22523(self : Fe) -> Fe {
  let t0 = self.sq()
  let t1 = t0.sq().sq()
  let t1 = t1.mul(self)
  let t0 = t0.mul(t1)
  let t2 = t0.sq()
  let t1 = t1.mul(t2)
  let t2 = t1.sq_k(5).mul(t1)
  let t3 = t2.sq_k(10).mul(t2)
  let t4 = t3.sq_k(20).mul(t3)
  let t3 = t4.sq_k(10).mul(t2)
  let t4 = t3.sq_k(50).mul(t3)
  let t5 = t4.sq_k(100).mul(t4)
  let t4 = t5.sq_k(50).mul(t3)
  t4.sq_k(2).mul(self)
}

///|
fn Fe::ct_is_negative_mask(self : Fe) -> UInt64 {
  let c = self.canonicalize()
  0UL - (c.l0 & 1UL)
}

///|
fn Fe::is_negative(self : Fe) -> Bool {
  self.ct_is_negative_mask() != 0UL
}

///|
fn Fe::ct_abs(self : Fe) -> Fe {
  let mask = self.ct_is_negative_mask()
  Fe::ct_select(mask, self.neg(), self)
}

///|
/// Constant-time field equality returning ALL_ONES if equal, else 0UL.
fn Fe::ct_eq(self : Fe, other : Fe) -> UInt64 {
  let d = self.sub(other).canonicalize()
  ct_is_zero_u64(d.l0 | d.l1 | d.l2 | d.l3 | d.l4)
}

///|
/// RFC 9496 §4.2 SQRT_RATIO_M1(u, v).
/// Returns (was_square_mask, r) where was_square_mask is ALL_ONES or 0UL.
fn Fe::sqrt_ratio_m1(u : Fe, v : Fe) -> (UInt64, Fe) {
  let v3 = v.sq().mul(v)
  let v7 = v3.sq().mul(v)
  let uv3 = u.mul(v3)
  let uv7 = u.mul(v7)
  let r0 = uv3.mul(uv7.pow22523())
  let check = v.mul(r0.sq())
  let neg_u = u.neg()
  let correct_sign_sqrt = check.ct_eq(u)
  let flipped_sign_sqrt = check.ct_eq(neg_u)
  let flipped_sign_sqrt_i = check.ct_eq(neg_u.mul(fe_sqrt_m1))
  let r_prime = fe_sqrt_m1.mul(r0)
  let r1 = Fe::ct_select(flipped_sign_sqrt | flipped_sign_sqrt_i, r_prime, r0)
  let r = r1.ct_abs()
  let was_square = correct_sign_sqrt | flipped_sign_sqrt
  (was_square, r)
}

///|
/// Strictly decode 32-byte little-endian canonical field element in [0, p - 1].
/// Does NOT mask the top bit; rejects length != 32 or value >= p (RFC 9496 §4.3.1).
fn Fe::from_bytes_canonical(bytes : Bytes) -> Result[Fe, String] {
  if bytes.length() != 32 {
    return Err("field element must be 32 bytes")
  }
  let w0 = load_u64_le(bytes, 0)
  let w1 = load_u64_le(bytes, 8)
  let w2 = load_u64_le(bytes, 16)
  let w3 = load_u64_le(bytes, 24)
  // Constant-time check: w < p iff w - p borrows out of bit 255.
  let (_, b0) = sub_borrow_u64(w0, P_W0, 0UL)
  let (_, b1) = sub_borrow_u64(w1, P_W1, b0)
  let (_, b2) = sub_borrow_u64(w2, P_W2, b1)
  let (_, b3) = sub_borrow_u64(w3, P_W3, b2)
  if b3 == 0UL {
    return Err("non-canonical field element encoding (>= p)")
  }
  let l0 = w0 & MASK51
  let l1 = ((w0 >> 51) | (w1 << 13)) & MASK51
  let l2 = ((w1 >> 38) | (w2 << 26)) & MASK51
  let l3 = ((w2 >> 25) | (w3 << 39)) & MASK51
  let l4 = (w3 >> 12) & MASK51
  Ok({ l0, l1, l2, l3, l4, })
}

///|
/// Decode 32-byte little-endian integer with top bit masked and reduced mod p (RFC 9496 §4.3.4 MAP).
fn Fe::from_bytes_unreduced(bytes : Bytes) -> Result[Fe, String] {
  if bytes.length() != 32 {
    return Err("field element must be 32 bytes")
  }
  let w0 = load_u64_le(bytes, 0)
  let w1 = load_u64_le(bytes, 8)
  let w2 = load_u64_le(bytes, 16)
  let w3 = load_u64_le(bytes, 24) & 0x7FFFFFFFFFFFFFFFUL
  let l0 = w0 & MASK51
  let l1 = ((w0 >> 51) | (w1 << 13)) & MASK51
  let l2 = ((w1 >> 38) | (w2 << 26)) & MASK51
  let l3 = ((w2 >> 25) | (w3 << 39)) & MASK51
  let l4 = (w3 >> 12) & MASK51
  Ok({ l0, l1, l2, l3, l4, }.canonicalize())
}

///|
/// Encode field element as canonical 32-byte little-endian representation in [0, p - 1].
fn Fe::to_bytes_canonical(self : Fe) -> Bytes {
  let c = self.canonicalize()
  let w0 = c.l0 | (c.l1 << 51)
  let w1 = (c.l1 >> 13) | (c.l2 << 38)
  let w2 = (c.l2 >> 26) | (c.l3 << 25)
  let w3 = (c.l3 >> 39) | (c.l4 << 12)
  let out = FixedArray::make(32, b'\x00')
  store_u64_le(out, 0, w0)
  store_u64_le(out, 8, w1)
  store_u64_le(out, 16, w2)
  store_u64_le(out, 24, w3)
  Bytes::from_array(out)
}

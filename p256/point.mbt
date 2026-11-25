// NIST P-256 (secp256r1) prime-order elliptic curve group:
//   E / F_p : y^2 = x^3 - 3*x + b
//   b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
// Uses homogeneous projective coordinates (X : Y : Z) with Renes-Costello-Batina (2015)
// complete addition (Algorithm 4) and exception-free doubling (Algorithm 6) for a = -3.
// Scalar multiplication uses a 4-bit fixed window with constant-time 16-entry table lookup.

// Curve constant b in Montgomery form.

///|
const B_MONT_0 : UInt64 = 0xd89cdf6229c4bddfUL

///|
const B_MONT_1 : UInt64 = 0xacf005cd78843090UL

///|
const B_MONT_2 : UInt64 = 0xe5a220abf7212ed6UL

///|
const B_MONT_3 : UInt64 = 0xdc30061d04874834UL

// Standard SEC2 P-256 base point G = (Gx, Gy) in Montgomery form.

///|
const GX_MONT_0 : UInt64 = 0x79e730d418a9143cUL

///|
const GX_MONT_1 : UInt64 = 0x75ba95fc5fedb601UL

///|
const GX_MONT_2 : UInt64 = 0x79fb732b77622510UL

///|
const GX_MONT_3 : UInt64 = 0x18905f76a53755c6UL

///|
const GY_MONT_0 : UInt64 = 0xddf25357ce95560aUL

///|
const GY_MONT_1 : UInt64 = 0x8b4ab8e4ba19e45cUL

///|
const GY_MONT_2 : UInt64 = 0xd2e88688dd21f325UL

///|
const GY_MONT_3 : UInt64 = 0x8571ff1825885d85UL

///|
fn curve_b() -> FieldElement {
  FieldElement::from_raw_mont(B_MONT_0, B_MONT_1, B_MONT_2, B_MONT_3)
}

///|
#derive(Debug)
pub struct P256Point {
  priv x : FieldElement
  priv y : FieldElement
  priv z : FieldElement
}

///|
pub impl Eq for P256Point with fn equal(self : P256Point, other : P256Point) -> Bool {
  self.ct_eq(other)
}

///|
pub fn P256Point::identity() -> P256Point {
  { x: FieldElement::zero(), y: FieldElement::one(), z: FieldElement::zero(), }
}

///|
pub fn P256Point::generator() -> P256Point {
  {
    x: FieldElement::from_raw_mont(GX_MONT_0, GX_MONT_1, GX_MONT_2, GX_MONT_3),
    y: FieldElement::from_raw_mont(GY_MONT_0, GY_MONT_1, GY_MONT_2, GY_MONT_3),
    z: FieldElement::one(),
  }
}

///|
pub fn P256Point::is_identity(self : P256Point) -> Bool {
  self.z.is_zero()
}

///|
pub fn P256Point::ct_eq(self : P256Point, other : P256Point) -> Bool {
  let z1_zero = self.z.ct_is_zero_mask()
  let z2_zero = other.z.ct_is_zero_mask()
  let both_zero = z1_zero & z2_zero
  let both_nonzero = (z1_zero ^ U64_ALL_ONES) & (z2_zero ^ U64_ALL_ONES)
  let x_eq = self.x.mul(other.z).ct_eq_mask(other.x.mul(self.z))
  let y_eq = self.y.mul(other.z).ct_eq_mask(other.y.mul(self.z))
  let eq_mask = both_zero | (both_nonzero & x_eq & y_eq)
  eq_mask != 0UL
}

///|
pub fn P256Point::ct_select(
  mask : UInt64,
  a : P256Point,
  b : P256Point,
) -> P256Point {
  {
    x: FieldElement::ct_select(mask, a.x, b.x),
    y: FieldElement::ct_select(mask, a.y, b.y),
    z: FieldElement::ct_select(mask, a.z, b.z),
  }
}

///|
pub fn P256Point::neg(self : P256Point) -> P256Point {
  { x: self.x, y: self.y.neg(), z: self.z, }
}

// Complete projective point addition for a = -3 short Weierstrass curves
// (Renes-Costello-Batina 2015, IACR ePrint 2015/1060, Algorithm 4).
// Handles O + P, P + O, P + P, P + (-P) = O, O + O uniformly with zero branches.

///|
pub fn P256Point::add(self : P256Point, other : P256Point) -> P256Point {
  let b = curve_b()
  let x1 = self.x
  let y1 = self.y
  let z1 = self.z
  let x2 = other.x
  let y2 = other.y
  let z2 = other.z

  let t0 = x1.mul(x2)
  let t1 = y1.mul(y2)
  let t2 = z1.mul(z2)
  let t3 = x1.add(y1)
  let t4 = x2.add(y2)
  let t3 = t3.mul(t4)
  let t4 = t0.add(t1)
  let t3 = t3.sub(t4)
  let t4 = y1.add(z1)
  let x3 = y2.add(z2)
  let t4 = t4.mul(x3)
  let x3 = t1.add(t2)
  let t4 = t4.sub(x3)
  let x3 = x1.add(z1)
  let y3 = x2.add(z2)
  let x3 = x3.mul(y3)
  let y3 = t0.add(t2)
  let y3 = x3.sub(y3)
  let z3 = b.mul(t2)
  let x3 = y3.sub(z3)
  let z3 = x3.add(x3)
  let x3 = x3.add(z3)
  let z3 = t1.sub(x3)
  let x3 = t1.add(x3)
  let y3 = b.mul(y3)
  let t1 = t2.add(t2)
  let t2 = t1.add(t2)
  let y3 = y3.sub(t2)
  let y3 = y3.sub(t0)
  let t1 = y3.add(y3)
  let y3 = t1.add(y3)
  let t1 = t0.add(t0)
  let t0 = t1.add(t0)
  let t0 = t0.sub(t2)
  let t1 = t4.mul(y3)
  let t2 = t0.mul(y3)
  let y3 = x3.mul(z3)
  let y3 = y3.add(t2)
  let x3 = t3.mul(x3)
  let x3 = x3.sub(t1)
  let z3 = t4.mul(z3)
  let t1 = t3.mul(t0)
  let z3 = z3.add(t1)
  { x: x3, y: y3, z: z3, }
}

// Exception-free projective point doubling for a = -3 short Weierstrass curves
// (Renes-Costello-Batina 2015, IACR ePrint 2015/1060, Algorithm 6).

///|
pub fn P256Point::double(self : P256Point) -> P256Point {
  let b = curve_b()
  let x = self.x
  let y = self.y
  let z = self.z

  let t0 = x.sq()
  let t1 = y.sq()
  let t2 = z.sq()
  let t3 = x.mul(y)
  let t3 = t3.add(t3)
  let z3 = x.mul(z)
  let z3 = z3.add(z3)
  let y3 = b.mul(t2)
  let y3 = y3.sub(z3)
  let x3 = y3.add(y3)
  let y3 = x3.add(y3)
  let x3 = t1.sub(y3)
  let y3 = t1.add(y3)
  let y3 = x3.mul(y3)
  let x3 = x3.mul(t3)
  let t3 = t2.add(t2)
  let t2 = t2.add(t3)
  let z3 = b.mul(z3)
  let z3 = z3.sub(t2)
  let z3 = z3.sub(t0)
  let t3 = z3.add(z3)
  let z3 = z3.add(t3)
  let t3 = t0.add(t0)
  let t0 = t3.add(t0)
  let t0 = t0.sub(t2)
  let t0 = t0.mul(z3)
  let y3 = y3.add(t0)
  let t0 = y.mul(z)
  let t0 = t0.add(t0)
  let z3 = t0.mul(z3)
  let x3 = x3.sub(z3)
  let z3 = t0.mul(t1)
  let z3 = z3.add(z3)
  let z3 = z3.add(z3)
  { x: x3, y: y3, z: z3, }
}

///|
pub fn P256Point::sub(self : P256Point, other : P256Point) -> P256Point {
  self.add(other.neg())
}

// Constant-time full-table scan over 16 precomputed multiples [0*P, 1*P, ..., 15*P].
// Never indexes the table with a secret value and never branches on a secret nibble.

///|
fn ct_table_lookup(table : FixedArray[P256Point], nibble : UInt64) -> P256Point {
  let mut acc = P256Point::identity()
  for i = 0; i < 16; i = i + 1 {
    let mask = ct_eq_u64(i.to_uint64(), nibble)
    acc = P256Point::ct_select(mask, table[i], acc)
  }
  acc
}

// Constant-time scalar multiplication via 4-bit fixed window + CT 16-entry table scan.

///|
pub fn P256Point::scalar_mul(self : P256Point, s : Scalar) -> P256Point {
  let table : FixedArray[P256Point] = FixedArray::make(
    16,
    P256Point::identity(),
  )
  table[1] = self
  for i = 2; i < 16; i = i + 1 {
    table[i] = table[i - 1].add(self)
  }

  let scalar_bytes = s.to_bytes()
  let mut acc = P256Point::identity()
  for byte_idx = 0; byte_idx < 32; byte_idx = byte_idx + 1 {
    let byte_val = scalar_bytes[byte_idx].to_uint64()
    let hi_nib = (byte_val >> 4) & 0x0fUL
    let lo_nib = byte_val & 0x0fUL

    acc = acc.double().double().double().double()
    let p_hi = ct_table_lookup(table, hi_nib)
    acc = acc.add(p_hi)

    acc = acc.double().double().double().double()
    let p_lo = ct_table_lookup(table, lo_nib)
    acc = acc.add(p_lo)
  }
  acc
}

///|
pub fn P256Point::scalar_base_mul(s : Scalar) -> P256Point {
  P256Point::generator().scalar_mul(s)
}

// RFC 9591 §6.4 SerializeElement: 33-byte SEC1 compressed encoding (0x02/0x03 || X_be).
// Rejects the identity element.

///|
pub fn P256Point::serialize_compressed(
  self : P256Point,
) -> Result[Bytes, String] {
  if self.is_identity() {
    return Err("cannot serialize identity element")
  }
  let z_inv = self.z.inv()
  let ax = self.x.mul(z_inv)
  let ay = self.y.mul(z_inv)
  let x_bytes = ax.to_bytes_be()
  let prefix : Byte = (2UL + ay.is_odd_bit()).to_byte()
  Ok(Bytes::makei(33, fn(i) { if i == 0 { prefix } else { x_bytes[i - 1] } }))
}

// RFC 9591 §6.4 DeserializeElement: strict 33-byte SEC1 compressed decoding.
// Only accepts prefixes 0x02 and 0x03, verifies x < p, verifies y^2 = x^3 - 3x + b
// has a square root in F_p, and selects the root with matching parity.
// Rejects identity (0x00), uncompressed (0x04), invalid prefixes, x >= p, and off-curve x.

///|
pub fn P256Point::deserialize_compressed(
  bytes : Bytes,
) -> Result[P256Point, String] {
  if bytes.length() != 33 {
    return Err("p256 compressed point must be 33 bytes")
  }
  let prefix = bytes[0]
  if prefix != b'\x02' && prefix != b'\x03' {
    return Err("p256 compressed point must start with 0x02 or 0x03")
  }
  let want_odd : UInt64 = prefix.to_uint64() & 1UL
  let x_bytes = Bytes::makei(32, fn(i) { bytes[i + 1] })
  let x = match FieldElement::from_bytes_be_strict(x_bytes) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  // rhs = x^3 - 3*x + b
  let x2 = x.sq()
  let x3 = x2.mul(x)
  let three_x = x.add(x).add(x)
  let rhs = x3.sub(three_x).add(curve_b())
  let y_root = match rhs.sqrt() {
    Some(r) => r
    None => return Err("p256 point not on curve (no square root)")
  }
  let y_odd = y_root.is_odd_bit()
  let flip_mask = ct_mask_from_bit(want_odd ^ y_odd)
  let y = FieldElement::ct_select(flip_mask, y_root.neg(), y_root)
  Ok({ x, y, z: FieldElement::one(), })
}

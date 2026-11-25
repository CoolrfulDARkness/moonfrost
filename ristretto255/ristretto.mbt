///|
/// Opaque RFC 9496 Ristretto255 prime-order group element.
/// Internal Ed25519 representation is strictly encapsulated per RFC 9496 §6.
#derive(Debug)
pub struct RistrettoPoint {
  priv point : EdwardsPoint
}

///|
pub fn RistrettoPoint::identity() -> RistrettoPoint {
  { point: EdwardsPoint::identity(), }
}

///|
pub fn RistrettoPoint::generator() -> RistrettoPoint {
  { point: EdwardsPoint::basepoint(), }
}

///|
pub fn RistrettoPoint::add(
  self : RistrettoPoint,
  other : RistrettoPoint,
) -> RistrettoPoint {
  { point: self.point.add(other.point), }
}

///|
pub fn RistrettoPoint::sub(
  self : RistrettoPoint,
  other : RistrettoPoint,
) -> RistrettoPoint {
  { point: self.point.sub(other.point), }
}

///|
pub fn RistrettoPoint::neg(self : RistrettoPoint) -> RistrettoPoint {
  { point: self.point.neg(), }
}

///|
/// RFC 9496 §4.3.3 constant-time equivalence test on internal representations:
/// CT_EQ(x1 * y2, y1 * x2) | CT_EQ(y1 * y2, x1 * x2).
pub fn RistrettoPoint::ct_eq(
  self : RistrettoPoint,
  other : RistrettoPoint,
) -> Bool {
  let p1 = self.point
  let p2 = other.point
  let eq1 = p1.x.mul(p2.y).ct_eq(p1.y.mul(p2.x))
  let eq2 = p1.y.mul(p2.y).ct_eq(p1.x.mul(p2.x))
  (eq1 | eq2) != 0UL
}

///|
pub impl Eq for RistrettoPoint with fn equal(self, other) {
  self.ct_eq(other)
}

///|
pub fn RistrettoPoint::is_identity(self : RistrettoPoint) -> Bool {
  self.ct_eq(RistrettoPoint::identity())
}

///|
pub fn RistrettoPoint::scalar_mul(
  self : RistrettoPoint,
  s : Scalar,
) -> RistrettoPoint {
  { point: self.point.scalar_mul(s), }
}

///|
pub fn RistrettoPoint::scalar_base_mul(s : Scalar) -> RistrettoPoint {
  { point: EdwardsPoint::basepoint().scalar_mul(s), }
}

///|
/// RFC 9496 §4.3.2 Encode: canonical 32-byte encoding of a ristretto255 group element.
pub fn RistrettoPoint::encode(self : RistrettoPoint) -> Bytes {
  let x0 = self.point.x
  let y0 = self.point.y
  let z0 = self.point.z
  let t0 = self.point.t
  let u1 = z0.add(y0).mul(z0.sub(y0))
  let u2 = x0.mul(y0)
  // Ignore was_square since u1 * u2^2 is always a square for valid internal representations.
  let (_, invsqrt) = Fe::sqrt_ratio_m1(Fe::one(), u1.mul(u2.sq()))
  let den1 = invsqrt.mul(u1)
  let den2 = invsqrt.mul(u2)
  let z_inv = den1.mul(den2).mul(t0)
  let ix0 = x0.mul(fe_sqrt_m1)
  let iy0 = y0.mul(fe_sqrt_m1)
  let enchanted_denominator = den1.mul(fe_invsqrt_a_minus_d)
  let rotate = t0.mul(z_inv).ct_is_negative_mask()
  let x = Fe::ct_select(rotate, iy0, x0)
  let y = Fe::ct_select(rotate, ix0, y0)
  let z = z0
  let den_inv = Fe::ct_select(rotate, enchanted_denominator, den2)
  let neg_xz = x.mul(z_inv).ct_is_negative_mask()
  let y = Fe::ct_select(neg_xz, y.neg(), y)
  let s = den_inv.mul(z.sub(y)).ct_abs()
  s.to_bytes_canonical()
}

///|
/// RFC 9496 §4.3.1 Decode: strictly decode a 32-byte canonical ristretto255 encoding.
/// Accepts 32 zero bytes as the group identity element.
pub fn RistrettoPoint::decode(bytes : Bytes) -> Result[RistrettoPoint, String] {
  let s = match Fe::from_bytes_canonical(bytes) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if s.is_negative() {
    return Err("invalid ristretto255 encoding: negative field element")
  }
  let one = Fe::one()
  let ss = s.sq()
  let u1 = one.sub(ss)
  let u2 = one.add(ss)
  let u2_sqr = u2.sq()
  let v = fe_d.mul(u1.sq()).neg().sub(u2_sqr)
  let (was_square_mask, invsqrt) = Fe::sqrt_ratio_m1(one, v.mul(u2_sqr))
  let den_x = invsqrt.mul(u2)
  let den_y = invsqrt.mul(den_x).mul(v)
  let x = s.add(s).mul(den_x).ct_abs()
  let y = u1.mul(den_y)
  let t = x.mul(y)
  let invalid_mask = (was_square_mask ^ ALL_ONES) |
    t.ct_is_negative_mask() |
    y.ct_eq(Fe::zero())
  if invalid_mask != 0UL {
    return Err("invalid ristretto255 encoding")
  }
  Ok({ point: { x, y, z: one, t, }, })
}

///|
/// RFC 9591 §6.2 SerializeElement: encode group element, rejecting the identity element.
pub fn RistrettoPoint::serialize_non_identity(
  self : RistrettoPoint,
) -> Result[Bytes, String] {
  if self.is_identity() {
    return Err("cannot serialize identity element")
  }
  Ok(self.encode())
}

///|
/// RFC 9591 §6.2 DeserializeElement: decode group element, rejecting the identity element.
pub fn RistrettoPoint::deserialize_non_identity(
  bytes : Bytes,
) -> Result[RistrettoPoint, String] {
  let p = match RistrettoPoint::decode(bytes) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if p.is_identity() {
    return Err("identity element is not permitted")
  }
  Ok(p)
}

///|
/// RFC 9496 §4.3.4 MAP(b[0:32]): Elligator2 map from a 32-byte slice to an internal point.
fn elligator_map_slice(bytes : Bytes, offset : Int32) -> EdwardsPoint {
  let slice = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    slice[i] = bytes[offset + i]
  }
  // slice is always 32 bytes so from_bytes_unreduced always returns Ok.
  let t = match Fe::from_bytes_unreduced(Bytes::from_array(slice)) {
    Ok(v) => v
    Err(_) => Fe::zero()
  }
  let one = Fe::one()
  let minus_one = Fe::minus_one()
  let r = fe_sqrt_m1.mul(t.sq())
  let u = r.add(one).mul(fe_one_minus_d_sq)
  let v = minus_one.sub(r.mul(fe_d)).mul(r.add(fe_d))
  let (was_square, s0) = Fe::sqrt_ratio_m1(u, v)
  let s_prime = s0.mul(t).ct_abs().neg()
  let s = Fe::ct_select(was_square, s0, s_prime)
  let c = Fe::ct_select(was_square, minus_one, r)
  let n_val = c.mul(r.sub(one)).mul(fe_d_minus_one_sq).sub(v)
  let w0 = s.add(s).mul(v)
  let w1 = n_val.mul(fe_sqrt_ad_minus_one)
  let ss = s.sq()
  let w2 = one.sub(ss)
  let w3 = one.add(ss)
  { x: w0.mul(w3), y: w2.mul(w1), z: w1.mul(w3), t: w0.mul(w2), }
}

///|
/// RFC 9496 §4.3.4 Element Derivation: map 64 uniform bytes to a ristretto255 group element.
/// Rejects length != 64.
pub fn RistrettoPoint::from_uniform_bytes(
  bytes : Bytes,
) -> Result[RistrettoPoint, String] {
  if bytes.length() != 64 {
    return Err("uniform bytes input must be 64 bytes")
  }
  let p1 = elligator_map_slice(bytes, 0)
  let p2 = elligator_map_slice(bytes, 32)
  Ok({ point: p1.add(p2), })
}

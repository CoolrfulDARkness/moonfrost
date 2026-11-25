///|
/// Extended Twisted Edwards coordinates (X, Y, Z, T) on Ed25519 (-x^2 + y^2 = 1 + d*x^2*y^2)
/// with complete unified addition, dedicated doubling, and constant-time 4-bit fixed-window
/// scalar multiplication (16-entry full-table CT scan).

///|
#derive(Debug)
priv struct EdwardsPoint {
  x : Fe
  y : Fe
  z : Fe
  t : Fe
}

///|
/// Ed25519 basepoint B in extended coordinates (X, Y, 1, X*Y).
let ed_base_x : Fe = {
  l0: 0x62d608f25d51aUL,
  l1: 0x412a4b4f6592aUL,
  l2: 0x75b7171a4b31dUL,
  l3: 0x1ff60527118feUL,
  l4: 0x216936d3cd6e5UL,
}

///|
let ed_base_y : Fe = {
  l0: 0x6666666666658UL,
  l1: 0x4ccccccccccccUL,
  l2: 0x1999999999999UL,
  l3: 0x3333333333333UL,
  l4: 0x6666666666666UL,
}

///|
let ed_base_t : Fe = {
  l0: 0x68ab3a5b7dda3UL,
  l1: 0x00eea2a5eadbbUL,
  l2: 0x2af8df483c27eUL,
  l3: 0x332b375274732UL,
  l4: 0x67875f0fd78b7UL,
}

///|
fn EdwardsPoint::identity() -> EdwardsPoint {
  { x: Fe::zero(), y: Fe::one(), z: Fe::one(), t: Fe::zero(), }
}

///|
fn EdwardsPoint::basepoint() -> EdwardsPoint {
  { x: ed_base_x, y: ed_base_y, z: Fe::one(), t: ed_base_t, }
}

///|
fn EdwardsPoint::neg(self : EdwardsPoint) -> EdwardsPoint {
  { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg(), }
}

///|
/// Complete unified addition formula (RFC 8032 §5.1.4 / Hisil et al. 2008).
fn EdwardsPoint::add(self : EdwardsPoint, other : EdwardsPoint) -> EdwardsPoint {
  let a = self.y.sub(self.x).mul(other.y.sub(other.x))
  let b = self.y.add(self.x).mul(other.y.add(other.x))
  let c = self.t.mul(fe_two_d).mul(other.t)
  let d = self.z.add(self.z).mul(other.z)
  let e = b.sub(a)
  let f = d.sub(c)
  let g = d.add(c)
  let h = b.add(a)
  { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h), }
}

///|
fn EdwardsPoint::sub(self : EdwardsPoint, other : EdwardsPoint) -> EdwardsPoint {
  self.add(other.neg())
}

///|
/// Dedicated point doubling formula (RFC 8032 §5.1.4 / Hisil et al. 2008).
fn EdwardsPoint::double(self : EdwardsPoint) -> EdwardsPoint {
  let a = self.x.sq()
  let b = self.y.sq()
  let z2 = self.z.sq()
  let c = z2.add(z2)
  let h = a.add(b)
  let e = h.sub(self.x.add(self.y).sq())
  let g = a.sub(b)
  let f = c.add(g)
  { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h), }
}

///|
/// Constant-time point select: returns if_true when mask == ALL_ONES, else if_false.
fn ct_select_point(
  mask : UInt64,
  if_true : EdwardsPoint,
  if_false : EdwardsPoint,
) -> EdwardsPoint {
  {
    x: Fe::ct_select(mask, if_true.x, if_false.x),
    y: Fe::ct_select(mask, if_true.y, if_false.y),
    z: Fe::ct_select(mask, if_true.z, if_false.z),
    t: Fe::ct_select(mask, if_true.t, if_false.t),
  }
}

///|
/// Full-table constant-time lookup over a 16-entry EdwardsPoint table.
/// Always scans every entry 0..15 using all-1/all-0 bitmasks; never indexes by secret nibble.
fn ct_lookup_point(
  table : FixedArray[EdwardsPoint],
  idx : UInt64,
) -> EdwardsPoint {
  let mut acc = EdwardsPoint::identity()
  for j = 0; j < 16; j = j + 1 {
    let mask = ct_eq_u64_mask(idx, j.to_uint64())
    acc = ct_select_point(mask, table[j], acc)
  }
  acc
}

///|
/// Constant-time 4-bit fixed-window scalar multiplication.
/// Precomputes table[i] = i * self for i in 0..15, then processes all 64 nibbles
/// from MSB to LSB with constant-time full-table scans and zero secret-dependent branches.
fn EdwardsPoint::scalar_mul(self : EdwardsPoint, s : Scalar) -> EdwardsPoint {
  let id = EdwardsPoint::identity()
  let table : FixedArray[EdwardsPoint] = FixedArray::make(16, id)
  table[1] = self
  for i = 2; i < 16; i = i + 1 {
    table[i] = table[i - 1].add(self)
  }
  let mut acc = ct_lookup_point(table, s.nibble(63))
  for k = 62; k >= 0; k = k - 1 {
    acc = acc.double().double().double().double()
    let q = ct_lookup_point(table, s.nibble(k))
    acc = acc.add(q)
  }
  acc
}

///|
/// Concrete RFC 9591 ciphersuite instantiations and uniform random scalar
/// generation (RFC 9591 Appendix D).

///|
/// RFC 9591 §6.2: FROST(ristretto255, SHA-512) ciphersuite.
pub fn ristretto255_sha512() -> SuiteOps[
  @ristretto255.Scalar,
  @ristretto255.RistrettoPoint,
] {
  {
    context_string: @ristretto255.CONTEXT_STRING,
    ne: @ristretto255.NE,
    ns: @ristretto255.NS,
    wide_bytes_len: 64,
    scalar_zero: @ristretto255.Scalar::zero,
    scalar_one: @ristretto255.Scalar::one,
    scalar_from_u32: @ristretto255.Scalar::from_u32,
    scalar_add: fn(a, b) { a.add(b) },
    scalar_sub: fn(a, b) { a.sub(b) },
    scalar_mul: fn(a, b) { a.mul(b) },
    scalar_neg: fn(a) { a.neg() },
    scalar_invert: fn(a) { a.invert() },
    scalar_is_zero: fn(a) { a.is_zero() },
    scalar_eq: fn(a, b) { a.ct_eq(b) },
    scalar_compare: fn(a, b) { a.compare(b) },
    serialize_scalar: fn(a) { a.to_bytes() },
    deserialize_scalar: @ristretto255.Scalar::from_bytes_strict,
    scalar_from_wide_bytes: @ristretto255.Scalar::from_bytes_mod_order_wide,
    element_identity: @ristretto255.RistrettoPoint::identity,
    element_generator: @ristretto255.RistrettoPoint::generator,
    element_add: fn(a, b) { a.add(b) },
    element_sub: fn(a, b) { a.sub(b) },
    element_neg: fn(a) { a.neg() },
    element_is_identity: fn(a) { a.is_identity() },
    element_eq: fn(a, b) { a.ct_eq(b) },
    scalar_mul_elem: fn(p, s) { p.scalar_mul(s) },
    scalar_base_mul: @ristretto255.RistrettoPoint::scalar_base_mul,
    serialize_element: fn(p) { p.serialize_non_identity() },
    deserialize_element: @ristretto255.RistrettoPoint::deserialize_non_identity,
    h1: @ristretto255.h1,
    h2: @ristretto255.h2,
    h3: @ristretto255.h3,
    h4: @ristretto255.h4,
    h5: @ristretto255.h5,
    h_dkg: @ristretto255.h_dkg,
  }
}

///|
/// RFC 9591 §6.4: FROST(P-256, SHA-256) ciphersuite.
pub fn p256_sha256() -> SuiteOps[@p256.Scalar, @p256.P256Point] {
  {
    context_string: @p256.CONTEXT_STRING,
    ne: @p256.NE,
    ns: @p256.NS,
    wide_bytes_len: 48,
    scalar_zero: @p256.Scalar::zero,
    scalar_one: @p256.Scalar::one,
    scalar_from_u32: @p256.Scalar::from_u32,
    scalar_add: fn(a, b) { a.add(b) },
    scalar_sub: fn(a, b) { a.sub(b) },
    scalar_mul: fn(a, b) { a.mul(b) },
    scalar_neg: fn(a) { a.neg() },
    scalar_invert: fn(a) { a.invert() },
    scalar_is_zero: fn(a) { a.is_zero() },
    scalar_eq: fn(a, b) { a.ct_eq(b) },
    scalar_compare: fn(a, b) { a.compare(b) },
    serialize_scalar: fn(a) { a.to_bytes() },
    deserialize_scalar: @p256.Scalar::from_bytes_strict,
    scalar_from_wide_bytes: @p256.Scalar::from_wide_be_bytes,
    element_identity: @p256.P256Point::identity,
    element_generator: @p256.P256Point::generator,
    element_add: fn(a, b) { a.add(b) },
    element_sub: fn(a, b) { a.sub(b) },
    element_neg: fn(a) { a.neg() },
    element_is_identity: fn(a) { a.is_identity() },
    element_eq: fn(a, b) { a.ct_eq(b) },
    scalar_mul_elem: fn(p, s) { p.scalar_mul(s) },
    scalar_base_mul: @p256.P256Point::scalar_base_mul,
    serialize_element: fn(p) { p.serialize_compressed() },
    deserialize_element: @p256.P256Point::deserialize_compressed,
    h1: @p256.h1,
    h2: @p256.h2,
    h3: @p256.h3,
    h4: @p256.h4,
    h5: @p256.h5,
    h_dkg: @p256.h_dkg,
  }
}

///|
/// RFC 9591 Appendix D uniform random scalar generation.
/// Uses Appendix D.2 wide reduction (64 bytes for ristretto255, 48 bytes for P-256)
/// with Appendix D.1 constant-time rejection sampling fallback.
pub fn[S, E] random_scalar(ops : SuiteOps[S, E], drbg : @crypto.Drbg) -> S {
  if ops.wide_bytes_len > 0 {
    let wide = drbg.next_bytes(ops.wide_bytes_len)
    match (ops.scalar_from_wide_bytes)(wide) {
      Ok(s) => return s
      Err(_) => ()
    }
  }
  while true {
    let candidate = drbg.next_bytes(ops.ns)
    match (ops.deserialize_scalar)(candidate) {
      Ok(s) => return s
      Err(_) => ()
    }
  }
  (ops.scalar_zero)()
}

///|
/// Generates a uniformly random non-zero scalar in [1, G.Order() - 1].
pub fn[S, E] random_nonzero_scalar(
  ops : SuiteOps[S, E],
  drbg : @crypto.Drbg,
) -> S {
  while true {
    let s = random_scalar(ops, drbg)
    if !(ops.scalar_is_zero)(s) {
      return s
    }
  }
  (ops.scalar_one)()
}

///|
/// Unified top-level facade for `CoolrfulDARkness/moonfrost`:
/// Pure MoonBit, zero-FFI, constant-time IETF RFC 9591 FROST threshold
/// Schnorr signatures (Ristretto255-SHA512 & P-256-SHA256), Feldman VSS,
/// and Pedersen DKG.

///|
pub using @frost {
  type FrostError,
  type SuiteOps,
  type KeyPackage,
  type PublicKeyPackage,
  type VssCommitment,
  type DkgRound1Secret,
  type DkgRound1Package,
  type DkgRound2Secret,
  type DkgRound2Package,
  type SigningCommitments,
  type SigningNonces,
  type CommitmentEntry,
  type SignatureShare,
  type Signature,
}

///|
pub using @crypto {type Drbg}

///|
/// Creates a deterministic ChaCha20/SHA-256 DRBG from `seed`.
pub fn drbg_from_seed(seed : Bytes) -> @crypto.Drbg {
  @crypto.Drbg::from_seed(seed)
}

///|
/// RFC 9591 §6.2: FROST(ristretto255, SHA-512) ciphersuite.
pub fn ristretto255_sha512() -> @frost.SuiteOps[
  @ristretto255.Scalar,
  @ristretto255.RistrettoPoint,
] {
  @frost.ristretto255_sha512()
}

///|
/// RFC 9591 §6.4: FROST(P-256, SHA-256) ciphersuite.
pub fn p256_sha256() -> @frost.SuiteOps[@p256.Scalar, @p256.P256Point] {
  @frost.p256_sha256()
}

///|
/// RFC 9591 Appendix C: Trusted Dealer threshold key generation.
pub fn[S, E] trusted_dealer_keygen(
  ops : @frost.SuiteOps[S, E],
  drbg : @crypto.Drbg,
  max_signers : Int32,
  min_signers : Int32,
) -> Result[
  (
    Array[@frost.KeyPackage[S, E]],
    @frost.PublicKeyPackage[E],
    @frost.VssCommitment[E],
  ),
  @frost.FrostError,
] {
  @frost.trusted_dealer_keygen(ops, drbg, max_signers, min_signers)
}

///|
/// Pedersen DKG Round 1.
pub fn[S, E] dkg_part1(
  ops : @frost.SuiteOps[S, E],
  identifier : Int32,
  max_signers : Int32,
  min_signers : Int32,
  drbg : @crypto.Drbg,
) -> Result[
  (@frost.DkgRound1Secret[S], @frost.DkgRound1Package[S, E]),
  @frost.FrostError,
] {
  @frost.dkg_part1(ops, identifier, max_signers, min_signers, drbg)
}

///|
/// Pedersen DKG Round 2.
pub fn[S, E] dkg_part2(
  ops : @frost.SuiteOps[S, E],
  secret : @frost.DkgRound1Secret[S],
  round1_packages : Array[@frost.DkgRound1Package[S, E]],
) -> Result[
  (@frost.DkgRound2Secret[S, E], Array[@frost.DkgRound2Package[S]]),
  @frost.FrostError,
] {
  @frost.dkg_part2(ops, secret, round1_packages)
}

///|
/// Pedersen DKG Round 3.
pub fn[S, E] dkg_part3(
  ops : @frost.SuiteOps[S, E],
  secret : @frost.DkgRound2Secret[S, E],
  round1_packages : Array[@frost.DkgRound1Package[S, E]],
  round2_packages : Array[@frost.DkgRound2Package[S]],
) -> Result[
  (@frost.KeyPackage[S, E], @frost.PublicKeyPackage[E]),
  @frost.FrostError,
] {
  @frost.dkg_part3(ops, secret, round1_packages, round2_packages)
}

///|
/// RFC 9591 §5.1: FROST Round 1 commitment generation.
pub fn[S, E] commit(
  ops : @frost.SuiteOps[S, E],
  secret_share : S,
  drbg : @crypto.Drbg,
) -> Result[
  (@frost.SigningNonces[S, E], @frost.SigningCommitments[E]),
  @frost.FrostError,
] {
  @frost.commit(ops, secret_share, drbg)
}

///|
/// RFC 9591 §5.2: FROST Round 2 signature share generation (consumes nonces).
pub fn[S, E] sign(
  ops : @frost.SuiteOps[S, E],
  key_package : @frost.KeyPackage[S, E],
  nonces : @frost.SigningNonces[S, E],
  msg : Bytes,
  commitment_list : Array[@frost.CommitmentEntry[E]],
) -> Result[@frost.SignatureShare[S], @frost.FrostError] {
  @frost.sign(ops, key_package, nonces, msg, commitment_list)
}

///|
/// RFC 9591 §5.3: Verifies a single participant's signature share.
pub fn[S, E] verify_signature_share(
  ops : @frost.SuiteOps[S, E],
  identifier : Int32,
  verifying_share : E,
  commitments : @frost.SigningCommitments[E],
  sig_share : S,
  commitment_list : Array[@frost.CommitmentEntry[E]],
  group_public_key : E,
  msg : Bytes,
) -> Result[Bool, @frost.FrostError] {
  @frost.verify_signature_share(
    ops, identifier, verifying_share, commitments, sig_share, commitment_list, group_public_key,
    msg,
  )
}

///|
/// RFC 9591 §5.3 & §5.4: Aggregates signature shares with Identifiable Abort.
pub fn[S, E] aggregate(
  ops : @frost.SuiteOps[S, E],
  commitment_list : Array[@frost.CommitmentEntry[E]],
  msg : Bytes,
  pub_keys : @frost.PublicKeyPackage[E],
  sig_shares : Array[@frost.SignatureShare[S]],
) -> Result[@frost.Signature[S, E], @frost.FrostError] {
  @frost.aggregate(ops, commitment_list, msg, pub_keys, sig_shares)
}

///|
/// RFC 9591 Appendix B: Single-party prime-order Schnorr signing.
pub fn[S, E] prime_order_sign(
  ops : @frost.SuiteOps[S, E],
  msg : Bytes,
  secret_key : S,
  drbg : @crypto.Drbg,
) -> Result[@frost.Signature[S, E], @frost.FrostError] {
  @frost.prime_order_sign(ops, msg, secret_key, drbg)
}

///|
/// RFC 9591 Appendix B: Prime-order Schnorr signature verification.
pub fn[S, E] prime_order_verify(
  ops : @frost.SuiteOps[S, E],
  msg : Bytes,
  sig : @frost.Signature[S, E],
  public_key : E,
) -> Result[Bool, @frost.FrostError] {
  @frost.prime_order_verify(ops, msg, sig, public_key)
}

///|
/// RFC 9591 Appendix A: Canonical signature serialization.
pub fn[S, E] serialize_signature(
  ops : @frost.SuiteOps[S, E],
  sig : @frost.Signature[S, E],
) -> Result[Bytes, @frost.FrostError] {
  @frost.serialize_signature(ops, sig)
}

///|
/// RFC 9591 Appendix A: Strict canonical signature deserialization.
pub fn[S, E] deserialize_signature(
  ops : @frost.SuiteOps[S, E],
  bytes : Bytes,
) -> Result[@frost.Signature[S, E], @frost.FrostError] {
  @frost.deserialize_signature(ops, bytes)
}

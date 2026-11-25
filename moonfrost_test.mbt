///|
test "moonfrost facade smoke test: ristretto255-sha512 and p256-sha256" {
  let msg = b"hello moonfrost"

  // FROST(ristretto255, SHA-512) 2-of-3
  let r_ops = @moonfrost.ristretto255_sha512()
  let r_drbg = @moonfrost.drbg_from_seed(b"facade-r255")
  let (r_kps, r_pub, _) = match
    @moonfrost.trusted_dealer_keygen(r_ops, r_drbg, 3, 2) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let (rn1, rc1) = @moonfrost.commit(r_ops, r_kps[0].signing_share, r_drbg).unwrap()
  let (rn3, rc3) = @moonfrost.commit(r_ops, r_kps[2].signing_share, r_drbg).unwrap()
  let r_comms : Array[@moonfrost.CommitmentEntry[_]] = [
    { identifier: 1, commitments: rc1, },
    { identifier: 3, commitments: rc3, },
  ]
  let rs1 = @moonfrost.sign(r_ops, r_kps[0], rn1, msg, r_comms).unwrap()
  let rs3 = @moonfrost.sign(r_ops, r_kps[2], rn3, msg, r_comms).unwrap()
  let r_sig = @moonfrost.aggregate(r_ops, r_comms, msg, r_pub, [rs1, rs3]).unwrap()
  let r_bytes = @moonfrost.serialize_signature(r_ops, r_sig).unwrap()
  let r_dec = @moonfrost.deserialize_signature(r_ops, r_bytes).unwrap()
  assert_eq(
    @moonfrost.prime_order_verify(r_ops, msg, r_dec, r_pub.verifying_key),
    Ok(true),
  )

  // FROST(P-256, SHA-256) 2-of-3
  let p_ops = @moonfrost.p256_sha256()
  let p_drbg = @moonfrost.drbg_from_seed(b"facade-p256")
  let (p_kps, p_pub, _) = match
    @moonfrost.trusted_dealer_keygen(p_ops, p_drbg, 3, 2) {
    Ok(v) => v
    Err(e) => fail("\{e}")
  }
  let (pn1, pc1) = @moonfrost.commit(p_ops, p_kps[0].signing_share, p_drbg).unwrap()
  let (pn2, pc2) = @moonfrost.commit(p_ops, p_kps[1].signing_share, p_drbg).unwrap()
  let p_comms : Array[@moonfrost.CommitmentEntry[_]] = [
    { identifier: 1, commitments: pc1, },
    { identifier: 2, commitments: pc2, },
  ]
  let ps1 = @moonfrost.sign(p_ops, p_kps[0], pn1, msg, p_comms).unwrap()
  let ps2 = @moonfrost.sign(p_ops, p_kps[1], pn2, msg, p_comms).unwrap()
  let p_sig = @moonfrost.aggregate(p_ops, p_comms, msg, p_pub, [ps1, ps2]).unwrap()
  let p_bytes = @moonfrost.serialize_signature(p_ops, p_sig).unwrap()
  let p_dec = @moonfrost.deserialize_signature(p_ops, p_bytes).unwrap()
  assert_eq(
    @moonfrost.prime_order_verify(p_ops, msg, p_dec, p_pub.verifying_key),
    Ok(true),
  )
}

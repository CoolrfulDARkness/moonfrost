///|
/// Comprehensive test suite for `CoolrfulDARkness/moonfrost/crypto`:
/// - FIPS 180-4 SHA-256 and SHA-512 official vectors (one-shot + streaming)
/// - RFC 9380 Appendix K.1 expand_message_xmd(SHA-256) official vectors
/// - RFC 9591 Appendix E.4 FROST(P-256, SHA-256) P1 hiding_nonce H3 verification
/// - Constant-time primitives and zeroization
/// - ChaCha20 DRBG determinism, chunking equivalence, and reseeding
/// - Hex encoding/decoding and edge-case rejections

///|
fn unwrap_bytes(r : Result[Bytes, String]) -> Bytes raise {
  match r {
    Ok(b) => b
    Err(e) => fail("unexpected error: " + e)
  }
}

///|
fn big_endian_bytes_mod(input : Bytes, modulus : Bytes) -> Bytes {
  // Simple schoolbook bit-by-bit modular reduction for test verification:
  // computes OS2IP(input) mod OS2IP(modulus) and returns 32-byte big-endian result.
  let n_len = modulus.length()
  let rem = FixedArray::make(n_len + 1, 0)
  for byte_idx = 0; byte_idx < input.length(); byte_idx = byte_idx + 1 {
    let cur = input[byte_idx].to_int()
    for bit = 7; bit >= 0; bit = bit - 1 {
      // rem = (rem << 1) | bit
      let mut carry = (cur >> bit) & 1
      for k = n_len; k >= 0; k = k - 1 {
        let v = (rem[k] << 1) | carry
        rem[k] = v & 0xff
        carry = v >> 8
      }
      // Compare rem >= modulus (modulus is aligned to rem[1..=n_len], rem[0] is extra MSB)
      let mut ge = rem[0] > 0
      if !ge {
        let mut decided = false
        for k = 0; k < n_len; k = k + 1 {
          let rv = rem[k + 1]
          let mv = modulus[k].to_int()
          if rv != mv {
            ge = rv > mv
            decided = true
            break
          }
        }
        if !decided {
          ge = true
        }
      }
      if ge {
        let mut borrow = 0
        for k = n_len - 1; k >= 0; k = k - 1 {
          let diff = rem[k + 1] - modulus[k].to_int() - borrow
          if diff < 0 {
            rem[k + 1] = diff + 256
            borrow = 1
          } else {
            rem[k + 1] = diff
            borrow = 0
          }
        }
        rem[0] = rem[0] - borrow
      }
    }
  }
  let out = FixedArray::make(n_len, b'\x00')
  for i = 0; i < n_len; i = i + 1 {
    out[i] = rem[i + 1].to_byte()
  }
  Bytes::from_array(out)
}

///|
test "sha256_fips_180_4_vectors" {
  // Empty string
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha256(Bytes::make(0, b'\x00'))),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  // "abc"
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha256(@crypto.ascii_bytes("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  // Two-block 56-byte message
  let msg56 = @crypto.ascii_bytes(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha256(msg56)),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  // Two-block 112-byte message
  let msg112 = @crypto.ascii_bytes(
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
  )
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha256(msg112)),
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
  )
  // Streaming chunked update and sha256_concat equivalence
  let h = @crypto.Sha256::new()
  h.update(@crypto.ascii_bytes("abcdbcdecdefdefgefgh"))
  h.update(@crypto.ascii_bytes("fghighijhijkijkljklm"))
  h.update(@crypto.ascii_bytes("klmnlmnomnopnopq"))
  assert_eq(
    @crypto.bytes_to_hex(h.finalize()),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  // Finalize is non-destructive
  assert_eq(
    @crypto.bytes_to_hex(h.finalize()),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  let c = @crypto.sha256_concat([
    @crypto.ascii_bytes("a"),
    @crypto.ascii_bytes("b"),
    @crypto.ascii_bytes("c"),
  ])
  assert_eq(
    @crypto.bytes_to_hex(c),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "sha512_fips_180_4_vectors" {
  // Empty string
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha512(Bytes::make(0, b'\x00'))),
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  // "abc"
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha512(@crypto.ascii_bytes("abc"))),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  // Two-block 112-byte message (112 + 1 + 16 = 129 > 128)
  let msg112 = @crypto.ascii_bytes(
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
  )
  assert_eq(
    @crypto.bytes_to_hex(@crypto.sha512(msg112)),
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
  // Streaming + sha512_concat across block boundaries
  let h = @crypto.Sha512::new()
  h.update(@crypto.ascii_bytes("abcdefghbcdefghicdefghijdefghijk"))
  h.update(@crypto.ascii_bytes("efghijklfghijklmghijklmnhijklmno"))
  h.update(@crypto.ascii_bytes("ijklmnopjklmnopqklmnopqrlmnopqrs"))
  h.update(@crypto.ascii_bytes("mnopqrstnopqrstu"))
  assert_eq(
    @crypto.bytes_to_hex(h.finalize()),
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
  let c = @crypto.sha512_concat([
    @crypto.ascii_bytes("ab"),
    @crypto.ascii_bytes("c"),
  ])
  assert_eq(
    @crypto.bytes_to_hex(c),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
}

///|
test "xmd_sha256_rfc9380_k1_vectors" {
  let dst = @crypto.ascii_bytes("QUUX-V01-CS02-with-expander-SHA256-128")
  // K.1 vector 1: msg = "", len = 0x20
  let v1 = unwrap_bytes(
    @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, 32),
  )
  assert_eq(
    @crypto.bytes_to_hex(v1),
    "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
  )
  // K.1 vector 2: msg = "abc", len = 0x20
  let v2 = unwrap_bytes(
    @crypto.expand_message_xmd_sha256(@crypto.ascii_bytes("abc"), dst, 32),
  )
  assert_eq(
    @crypto.bytes_to_hex(v2),
    "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
  )
  // K.1 vector 3: msg = "abcdef0123456789", len = 0x20
  let v3 = unwrap_bytes(
    @crypto.expand_message_xmd_sha256(
      @crypto.ascii_bytes("abcdef0123456789"),
      dst,
      32,
    ),
  )
  assert_eq(
    @crypto.bytes_to_hex(v3),
    "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
  )
  // K.1 vector 6: msg = "", len = 0x80 (4 blocks, exercises b_1..b_4 & strxor)
  let v6 = unwrap_bytes(
    @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, 128),
  )
  assert_eq(
    @crypto.bytes_to_hex(v6),
    "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
  )
  // K.1 vector 7: msg = "abc", len = 0x80
  let v7 = unwrap_bytes(
    @crypto.expand_message_xmd_sha256(@crypto.ascii_bytes("abc"), dst, 128),
  )
  assert_eq(
    @crypto.bytes_to_hex(v7),
    "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
  )
  // Boundary checks
  assert_eq(
    unwrap_bytes(
      @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, 0),
    ).length(),
    0,
  )
  assert_true(
    @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, -1)
    is Err(_),
  )
  assert_true(
    @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, 8161)
    is Err(_),
  )
  assert_true(
    @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, 65536)
    is Err(_),
  )
  assert_true(
    @crypto.expand_message_xmd_sha256(
      Bytes::make(0, b'\x00'),
      Bytes::make(256, b'\x00'),
      32,
    )
    is Err(_),
  )
  // Max valid DST (255 bytes) and max valid ell (255 * 32 = 8160)
  assert_eq(
    unwrap_bytes(
      @crypto.expand_message_xmd_sha256(
        Bytes::make(0, b'\x00'),
        Bytes::make(255, b'\x00'),
        32,
      ),
    ).length(),
    32,
  )
  assert_eq(
    unwrap_bytes(
      @crypto.expand_message_xmd_sha256(Bytes::make(0, b'\x00'), dst, 8160),
    ).length(),
    8160,
  )
}

///|
test "xmd_sha256_rfc9591_e4_p1_hiding_nonce_h3" {
  // RFC 9591 Appendix E.4 FROST(P-256, SHA-256)
  // H3(random_bytes || SerializeScalar(sk_1)) -> P1 hiding_nonce
  let p1_rand = unwrap_bytes(
    @crypto.hex_to_bytes(
      "ec4c891c85fee802a9d757a67d1252e7f4e5efb8a538991ac18fbd0e06fb6fd3",
    ),
  )
  let p1_share = unwrap_bytes(
    @crypto.hex_to_bytes(
      "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
    ),
  )
  let dst = @crypto.ascii_bytes("FROST-P256-SHA256-v1nonce")
  let uniform_bytes = unwrap_bytes(
    @crypto.expand_message_xmd_sha256(
      @crypto.concat_bytes([p1_rand, p1_share]),
      dst,
      48,
    ),
  )
  assert_eq(uniform_bytes.length(), 48)
  let p256_order = unwrap_bytes(
    @crypto.hex_to_bytes(
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ),
  )
  let hiding_nonce = big_endian_bytes_mod(uniform_bytes, p256_order)
  assert_eq(
    @crypto.bytes_to_hex(hiding_nonce),
    "9f0542a5ba879a58f255c09f06da7102ef6a2dec6279700c656d58394d8facd4",
  )
}

///|
test "ct_primitives_and_zeroize" {
  // ct_mask_from_bit
  assert_eq(@crypto.ct_mask_from_bit(0UL), 0UL)
  assert_eq(@crypto.ct_mask_from_bit(1UL), 0xffffffffffffffffUL)
  assert_eq(@crypto.ct_mask_from_bit(2UL), 0UL)
  assert_eq(@crypto.ct_mask_from_bit(3UL), 0xffffffffffffffffUL)
  // ct_is_zero_u64
  assert_eq(@crypto.ct_is_zero_u64(0UL), 0xffffffffffffffffUL)
  assert_eq(@crypto.ct_is_zero_u64(1UL), 0UL)
  assert_eq(@crypto.ct_is_zero_u64(0x7fffffffffffffffUL), 0UL)
  assert_eq(@crypto.ct_is_zero_u64(0x8000000000000000UL), 0UL)
  assert_eq(@crypto.ct_is_zero_u64(0xffffffffffffffffUL), 0UL)
  // ct_eq_u64
  assert_eq(@crypto.ct_eq_u64(42UL, 42UL), 0xffffffffffffffffUL)
  assert_eq(@crypto.ct_eq_u64(0UL, 0UL), 0xffffffffffffffffUL)
  assert_eq(
    @crypto.ct_eq_u64(0xffffffffffffffffUL, 0xffffffffffffffffUL),
    0xffffffffffffffffUL,
  )
  assert_eq(@crypto.ct_eq_u64(42UL, 43UL), 0UL)
  assert_eq(@crypto.ct_eq_u64(0UL, 0x8000000000000000UL), 0UL)
  // ct_select_u64 / u32 / byte
  assert_eq(
    @crypto.ct_select_u64(
      0xffffffffffffffffUL, 0x1122334455667788UL, 0x99aabbccddeeff00UL,
    ),
    0x1122334455667788UL,
  )
  assert_eq(
    @crypto.ct_select_u64(0UL, 0x1122334455667788UL, 0x99aabbccddeeff00UL),
    0x99aabbccddeeff00UL,
  )
  assert_eq(
    @crypto.ct_select_u32(0xffffffffU, 0xdeadbeefU, 0xcafebabeU),
    0xdeadbeefU,
  )
  assert_eq(@crypto.ct_select_u32(0U, 0xdeadbeefU, 0xcafebabeU), 0xcafebabeU)
  assert_eq(@crypto.ct_select_byte(0xffffffffU, b'\xaa', b'\x55'), b'\xaa')
  assert_eq(@crypto.ct_select_byte(0xffU, b'\xaa', b'\x55'), b'\xaa')
  assert_eq(@crypto.ct_select_byte(0U, b'\xaa', b'\x55'), b'\x55')
  // ct_eq_bytes / ct_eq_fixed_bytes
  let a = @crypto.ascii_bytes("moonfrost")
  let b = @crypto.ascii_bytes("moonfrost")
  let c = @crypto.ascii_bytes("moonfrosT")
  let d = @crypto.ascii_bytes("moon")
  assert_true(@crypto.ct_eq_bytes(a, b))
  assert_true(!@crypto.ct_eq_bytes(a, c))
  assert_true(!@crypto.ct_eq_bytes(a, d))
  let fa : FixedArray[Byte] = [b'\x01', b'\x02', b'\x03']
  let fb : FixedArray[Byte] = [b'\x01', b'\x02', b'\x03']
  let fc : FixedArray[Byte] = [b'\x01', b'\x02', b'\x04']
  assert_true(@crypto.ct_eq_fixed_bytes(fa, fb))
  assert_true(!@crypto.ct_eq_fixed_bytes(fa, fc))
  // zeroize
  @crypto.zeroize_bytes(fa)
  assert_eq(fa[0], b'\x00')
  assert_eq(fa[1], b'\x00')
  assert_eq(fa[2], b'\x00')
  let fu : FixedArray[UInt64] = [0x1234UL, 0xffffffffffffffffUL, 42UL]
  @crypto.zeroize_u64(fu)
  assert_eq(fu[0], 0UL)
  assert_eq(fu[1], 0UL)
  assert_eq(fu[2], 0UL)
}

///|
test "drbg_determinism_and_reseed" {
  let seed = @crypto.ascii_bytes("moonfrost-test-seed-1")
  let d1 = @crypto.Drbg::from_seed(seed)
  let d2 = @crypto.Drbg::from_seed(seed)
  let b1 = d1.next_bytes(96)
  let b2 = @crypto.concat_bytes([
    d2.next_bytes(17),
    d2.next_bytes(47),
    d2.next_bytes(32),
  ])
  assert_eq(b1.length(), 96)
  assert_true(@crypto.ct_eq_bytes(b1, b2))
  // Different seed produces different stream
  let d3 = @crypto.Drbg::from_seed(@crypto.ascii_bytes("moonfrost-test-seed-2"))
  assert_true(!@crypto.ct_eq_bytes(b1, d3.next_bytes(96)))
  // Zero / negative length returns empty bytes
  assert_eq(d1.next_bytes(0).length(), 0)
  assert_eq(d1.next_bytes(-5).length(), 0)
  // Reseed changes stream deterministically
  let d4 = @crypto.Drbg::from_seed(seed)
  let _ = d4.next_bytes(96)
  let d5 = @crypto.Drbg::from_seed(seed)
  let _ = d5.next_bytes(96)
  let no_reseed = d5.next_bytes(32)
  d1.reseed(@crypto.ascii_bytes("extra-entropy"))
  d4.reseed(@crypto.ascii_bytes("extra-entropy"))
  let after_reseed_1 = d1.next_bytes(32)
  let after_reseed_4 = d4.next_bytes(32)
  assert_true(@crypto.ct_eq_bytes(after_reseed_1, after_reseed_4))
  assert_true(!@crypto.ct_eq_bytes(after_reseed_1, no_reseed))
}

///|
test "hex_and_bytes_helpers" {
  let raw = unwrap_bytes(@crypto.hex_to_bytes("00010a0fFfABcd"))
  assert_eq(@crypto.bytes_to_hex(raw), "00010a0fffabcd")
  assert_eq(unwrap_bytes(@crypto.hex_to_bytes("")).length(), 0)
  assert_eq(@crypto.bytes_to_hex(Bytes::make(0, b'\x00')), "")
  // Reject odd length
  assert_true(@crypto.hex_to_bytes("a") is Err(_))
  assert_true(@crypto.hex_to_bytes("abc") is Err(_))
  // Reject invalid characters
  assert_true(@crypto.hex_to_bytes("0g") is Err(_))
  assert_true(@crypto.hex_to_bytes("zz") is Err(_))
  assert_true(@crypto.hex_to_bytes(" 0") is Err(_))
  assert_true(@crypto.hex_to_bytes("0x01") is Err(_))
  // concat_bytes and ascii_bytes
  let joined = @crypto.concat_bytes([
    @crypto.ascii_bytes("hello"),
    Bytes::make(0, b'\x00'),
    @crypto.ascii_bytes("-world"),
  ])
  assert_eq(@crypto.bytes_to_hex(joined), "68656c6c6f2d776f726c64")
}

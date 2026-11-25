///|
/// FIPS 180-4 SHA-512 implementation (pure MoonBit, zero FFI).

///|
let sha512_k : FixedArray[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
/// Streaming SHA-512 hash state.
pub struct Sha512 {
  priv state : FixedArray[UInt64]
  priv buf : FixedArray[Byte]
  priv mut buf_len : Int32
  priv mut total_bytes_lo : UInt64
  priv mut total_bytes_hi : UInt64
}

///|
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn read_be_u64(buf : FixedArray[Byte], offset : Int32) -> UInt64 {
  (buf[offset].to_uint64() << 56) |
  (buf[offset + 1].to_uint64() << 48) |
  (buf[offset + 2].to_uint64() << 40) |
  (buf[offset + 3].to_uint64() << 32) |
  (buf[offset + 4].to_uint64() << 24) |
  (buf[offset + 5].to_uint64() << 16) |
  (buf[offset + 6].to_uint64() << 8) |
  buf[offset + 7].to_uint64()
}

///|
fn sha512_compress(
  state : FixedArray[UInt64],
  block : FixedArray[Byte],
) -> Unit {
  let w = FixedArray::make(80, 0UL)
  for i = 0; i < 16; i = i + 1 {
    w[i] = read_be_u64(block, i * 8)
  }
  for i = 16; i < 80; i = i + 1 {
    let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
    let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  for i = 0; i < 80; i = i + 1 {
    let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    let ch = (e & f) ^ (e.lnot() & g)
    let temp1 = h + s1 + ch + sha512_k[i] + w[i]
    let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

///|
/// Creates a new SHA-512 streaming hasher initialized with FIPS 180-4 IV.
pub fn Sha512::new() -> Sha512 {
  {
    state: [
      0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
      0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
    ],
    buf: FixedArray::make(128, b'\x00'),
    buf_len: 0,
    total_bytes_lo: 0UL,
    total_bytes_hi: 0UL,
  }
}

///|
/// Feeds `data` into the SHA-512 streaming state.
pub fn Sha512::update(self : Sha512, data : Bytes) -> Unit {
  let len = data.length()
  let add = len.to_uint64()
  let new_lo = self.total_bytes_lo + add
  if new_lo < self.total_bytes_lo {
    self.total_bytes_hi = self.total_bytes_hi + 1UL
  }
  self.total_bytes_lo = new_lo
  let mut offset = 0
  if self.buf_len > 0 {
    while offset < len && self.buf_len < 128 {
      self.buf[self.buf_len] = data[offset]
      self.buf_len = self.buf_len + 1
      offset = offset + 1
    }
    if self.buf_len == 128 {
      sha512_compress(self.state, self.buf)
      self.buf_len = 0
    }
  }
  while len - offset >= 128 {
    for i = 0; i < 128; i = i + 1 {
      self.buf[i] = data[offset + i]
    }
    sha512_compress(self.state, self.buf)
    offset = offset + 128
  }
  while offset < len {
    self.buf[self.buf_len] = data[offset]
    self.buf_len = self.buf_len + 1
    offset = offset + 1
  }
}

///|
/// Securely wipes the internal SHA-512 state and input buffer.
pub fn Sha512::zeroize(self : Sha512) -> Unit {
  zeroize_u64(self.state)
  zeroize_bytes(self.buf)
  self.buf_len = 0
  self.total_bytes_lo = 0UL
  self.total_bytes_hi = 0UL
}

///|
/// Finalizes the SHA-512 hash and returns the 64-byte digest.
/// Operates on a copy of internal state so the hasher remains usable.
pub fn Sha512::finalize(self : Sha512) -> Bytes {
  let st = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    st[i] = self.state[i]
  }
  let block = FixedArray::make(128, b'\x00')
  for i = 0; i < self.buf_len; i = i + 1 {
    block[i] = self.buf[i]
  }
  block[self.buf_len] = b'\x80'
  let mut pos = self.buf_len + 1
  if pos > 112 {
    while pos < 128 {
      block[pos] = b'\x00'
      pos = pos + 1
    }
    sha512_compress(st, block)
    for i = 0; i < 112; i = i + 1 {
      block[i] = b'\x00'
    }
  } else {
    while pos < 112 {
      block[pos] = b'\x00'
      pos = pos + 1
    }
  }
  let bits_hi = (self.total_bytes_hi << 3) | (self.total_bytes_lo >> 61)
  let bits_lo = self.total_bytes_lo << 3
  for i = 0; i < 8; i = i + 1 {
    block[112 + i] = ((bits_hi >> (56 - i * 8)) & 0xffUL).to_byte()
    block[120 + i] = ((bits_lo >> (56 - i * 8)) & 0xffUL).to_byte()
  }
  sha512_compress(st, block)
  let out = FixedArray::make(64, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let v = st[i]
    out[i * 8] = ((v >> 56) & 0xffUL).to_byte()
    out[i * 8 + 1] = ((v >> 48) & 0xffUL).to_byte()
    out[i * 8 + 2] = ((v >> 40) & 0xffUL).to_byte()
    out[i * 8 + 3] = ((v >> 32) & 0xffUL).to_byte()
    out[i * 8 + 4] = ((v >> 24) & 0xffUL).to_byte()
    out[i * 8 + 5] = ((v >> 16) & 0xffUL).to_byte()
    out[i * 8 + 6] = ((v >> 8) & 0xffUL).to_byte()
    out[i * 8 + 7] = (v & 0xffUL).to_byte()
  }
  zeroize_u64(st)
  zeroize_bytes(block)
  Bytes::from_array(out)
}

///|
/// One-shot SHA-512 hash of `data`, returning a 64-byte digest.
pub fn sha512(data : Bytes) -> Bytes {
  let h = Sha512::new()
  h.update(data)
  let digest = h.finalize()
  h.zeroize()
  digest
}

///|
/// One-shot SHA-512 hash over the concatenation of `parts`.
pub fn sha512_concat(parts : Array[Bytes]) -> Bytes {
  let h = Sha512::new()
  for i = 0; i < parts.length(); i = i + 1 {
    h.update(parts[i])
  }
  let digest = h.finalize()
  h.zeroize()
  digest
}

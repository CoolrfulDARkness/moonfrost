///|
/// FIPS 180-4 SHA-256 implementation (pure MoonBit, zero FFI).

///|
let sha256_k : FixedArray[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
/// Streaming SHA-256 hash state.
pub struct Sha256 {
  priv state : FixedArray[UInt32]
  priv buf : FixedArray[Byte]
  priv mut buf_len : Int32
  priv mut total_bytes : UInt64
}

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
fn read_be_u32(buf : FixedArray[Byte], offset : Int32) -> UInt32 {
  (buf[offset].to_uint() << 24) |
  (buf[offset + 1].to_uint() << 16) |
  (buf[offset + 2].to_uint() << 8) |
  buf[offset + 3].to_uint()
}

///|
fn sha256_compress(
  state : FixedArray[UInt32],
  block : FixedArray[Byte],
) -> Unit {
  let w = FixedArray::make(64, 0U)
  for i = 0; i < 16; i = i + 1 {
    w[i] = read_be_u32(block, i * 4)
  }
  for i = 16; i < 64; i = i + 1 {
    let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
    let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
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
  for i = 0; i < 64; i = i + 1 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let temp1 = h + s1 + ch + sha256_k[i] + w[i]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
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
/// Creates a new SHA-256 streaming hasher initialized with FIPS 180-4 IV.
pub fn Sha256::new() -> Sha256 {
  {
    state: [
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
      0x1f83d9abU, 0x5be0cd19U,
    ],
    buf: FixedArray::make(64, b'\x00'),
    buf_len: 0,
    total_bytes: 0UL,
  }
}

///|
/// Feeds `data` into the SHA-256 streaming state.
pub fn Sha256::update(self : Sha256, data : Bytes) -> Unit {
  let len = data.length()
  self.total_bytes = self.total_bytes + len.to_uint64()
  let mut offset = 0
  if self.buf_len > 0 {
    while offset < len && self.buf_len < 64 {
      self.buf[self.buf_len] = data[offset]
      self.buf_len = self.buf_len + 1
      offset = offset + 1
    }
    if self.buf_len == 64 {
      sha256_compress(self.state, self.buf)
      self.buf_len = 0
    }
  }
  while offset + 64 <= len {
    for i = 0; i < 64; i = i + 1 {
      self.buf[i] = data[offset + i]
    }
    sha256_compress(self.state, self.buf)
    offset = offset + 64
  }
  while offset < len {
    self.buf[self.buf_len] = data[offset]
    self.buf_len = self.buf_len + 1
    offset = offset + 1
  }
}

///|
/// Finalizes the SHA-256 hash and returns the 32-byte digest.
/// Operates on a copy of internal state so the hasher remains usable.
pub fn Sha256::finalize(self : Sha256) -> Bytes {
  let st = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    st[i] = self.state[i]
  }
  let block = FixedArray::make(64, b'\x00')
  for i = 0; i < self.buf_len; i = i + 1 {
    block[i] = self.buf[i]
  }
  block[self.buf_len] = b'\x80'
  let mut pos = self.buf_len + 1
  if pos > 56 {
    while pos < 64 {
      block[pos] = b'\x00'
      pos = pos + 1
    }
    sha256_compress(st, block)
    for i = 0; i < 56; i = i + 1 {
      block[i] = b'\x00'
    }
  } else {
    while pos < 56 {
      block[pos] = b'\x00'
      pos = pos + 1
    }
  }
  let total_bits = self.total_bytes << 3
  for i = 0; i < 8; i = i + 1 {
    block[56 + i] = ((total_bits >> (56 - i * 8)) & 0xffUL).to_byte()
  }
  sha256_compress(st, block)
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let v = st[i]
    out[i * 4] = ((v >> 24) & 0xffU).to_byte()
    out[i * 4 + 1] = ((v >> 16) & 0xffU).to_byte()
    out[i * 4 + 2] = ((v >> 8) & 0xffU).to_byte()
    out[i * 4 + 3] = (v & 0xffU).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// One-shot SHA-256 hash of `data`, returning a 32-byte digest.
pub fn sha256(data : Bytes) -> Bytes {
  let h = Sha256::new()
  h.update(data)
  h.finalize()
}

///|
/// One-shot SHA-256 hash over the concatenation of `parts`.
pub fn sha256_concat(parts : Array[Bytes]) -> Bytes {
  let h = Sha256::new()
  for i = 0; i < parts.length(); i = i + 1 {
    h.update(parts[i])
  }
  h.finalize()
}

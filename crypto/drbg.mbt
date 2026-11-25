///|
/// Pure MoonBit deterministic CSPRNG based on RFC 8439 ChaCha20 with SHA-256
/// key derivation and reseeding.

///|
/// Deterministic ChaCha20-based DRBG.
pub struct Drbg {
  priv key : FixedArray[UInt32]
  priv nonce : FixedArray[UInt32]
  priv mut counter : UInt32
  priv buf : FixedArray[Byte]
  priv mut buf_pos : Int32
}

///|
fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn read_le_u32_bytes(b : Bytes, offset : Int32) -> UInt32 {
  b[offset].to_uint() |
  (b[offset + 1].to_uint() << 8) |
  (b[offset + 2].to_uint() << 16) |
  (b[offset + 3].to_uint() << 24)
}

///|
fn read_le_u32_fixed(b : FixedArray[Byte], offset : Int32) -> UInt32 {
  b[offset].to_uint() |
  (b[offset + 1].to_uint() << 8) |
  (b[offset + 2].to_uint() << 16) |
  (b[offset + 3].to_uint() << 24)
}

///|
fn write_le_u32(out : FixedArray[Byte], offset : Int32, v : UInt32) -> Unit {
  out[offset] = (v & 0xffU).to_byte()
  out[offset + 1] = ((v >> 8) & 0xffU).to_byte()
  out[offset + 2] = ((v >> 16) & 0xffU).to_byte()
  out[offset + 3] = ((v >> 24) & 0xffU).to_byte()
}

///|
fn chacha20_quarter_round(
  st : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  st[a] = st[a] + st[b]
  st[d] = rotl32(st[d] ^ st[a], 16)
  st[c] = st[c] + st[d]
  st[b] = rotl32(st[b] ^ st[c], 12)
  st[a] = st[a] + st[b]
  st[d] = rotl32(st[d] ^ st[a], 8)
  st[c] = st[c] + st[d]
  st[b] = rotl32(st[b] ^ st[c], 7)
}

///|
fn chacha20_block(
  key : FixedArray[UInt32],
  counter : UInt32,
  nonce : FixedArray[UInt32],
  out : FixedArray[Byte],
) -> Unit {
  let init = FixedArray::make(16, 0U)
  // "expand 32-byte k"
  init[0] = 0x61707865U
  init[1] = 0x3320646eU
  init[2] = 0x79622d32U
  init[3] = 0x6b206574U
  for i = 0; i < 8; i = i + 1 {
    init[4 + i] = key[i]
  }
  init[12] = counter
  init[13] = nonce[0]
  init[14] = nonce[1]
  init[15] = nonce[2]
  let work = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    work[i] = init[i]
  }
  for _r = 0; _r < 10; _r = _r + 1 {
    // Column rounds
    chacha20_quarter_round(work, 0, 4, 8, 12)
    chacha20_quarter_round(work, 1, 5, 9, 13)
    chacha20_quarter_round(work, 2, 6, 10, 14)
    chacha20_quarter_round(work, 3, 7, 11, 15)
    // Diagonal rounds
    chacha20_quarter_round(work, 0, 5, 10, 15)
    chacha20_quarter_round(work, 1, 6, 11, 12)
    chacha20_quarter_round(work, 2, 7, 8, 13)
    chacha20_quarter_round(work, 3, 4, 9, 14)
  }
  for i = 0; i < 16; i = i + 1 {
    write_le_u32(out, i * 4, work[i] + init[i])
  }
  zeroize_u32(init)
  zeroize_u32(work)
}

///|
fn Drbg::increment_nonce(self : Drbg) -> Unit {
  self.nonce[0] = self.nonce[0] + 1U
  if self.nonce[0] == 0U {
    self.nonce[1] = self.nonce[1] + 1U
    if self.nonce[1] == 0U {
      self.nonce[2] = self.nonce[2] + 1U
    }
  }
}

///|
fn Drbg::refill(self : Drbg) -> Unit {
  chacha20_block(self.key, self.counter, self.nonce, self.buf)
  self.buf_pos = 0
  self.counter = self.counter + 1U
  if self.counter == 0U {
    self.increment_nonce()
  }
}

///|
/// Creates a deterministic `Drbg` seeded via SHA-256 of `seed`.
pub fn Drbg::from_seed(seed : Bytes) -> Drbg {
  let key_bytes = sha256(seed)
  let key = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    key[i] = read_le_u32_bytes(key_bytes, i * 4)
  }
  {
    key,
    nonce: [0U, 0U, 0U],
    counter: 0U,
    buf: FixedArray::make(64, b'\x00'),
    buf_pos: 64,
  }
}

///|
/// Generates `len` pseudorandom bytes from the DRBG stream with DJB
/// fast-key-erasure ratcheting for backtracking resistance (forward secrecy).
/// Returns empty `Bytes` if `len <= 0`.
pub fn Drbg::next_bytes(self : Drbg, len : Int32) -> Bytes {
  if len <= 0 {
    return Bytes::make(0, b'\x00')
  }
  let out = FixedArray::make(len, b'\x00')
  let mut offset = 0
  while offset < len {
    if self.buf_pos >= 64 {
      self.refill()
    }
    let avail = 64 - self.buf_pos
    let need = len - offset
    let take = if avail < need { avail } else { need }
    for i = 0; i < take; i = i + 1 {
      out[offset + i] = self.buf[self.buf_pos + i]
      self.buf[self.buf_pos + i] = b'\x00'
    }
    self.buf_pos = self.buf_pos + take
    offset = offset + take
  }
  // DJB fast-key-erasure key ratchet: derive a fresh 256-bit key directly from
  // unused keystream bytes, wipe the buffer, reset counter, and advance nonce.
  if self.buf_pos > 32 {
    self.refill()
  }
  for i = 0; i < 8; i = i + 1 {
    self.key[i] = read_le_u32_fixed(self.buf, self.buf_pos + i * 4)
  }
  zeroize_bytes(self.buf)
  self.buf_pos = 64
  self.counter = 0U
  self.increment_nonce()
  Bytes::from_array(out)
}

///|
/// Securely wipes all internal DRBG key, nonce, and buffer state.
pub fn Drbg::zeroize(self : Drbg) -> Unit {
  zeroize_u32(self.key)
  zeroize_u32(self.nonce)
  zeroize_bytes(self.buf)
  self.counter = 0U
  self.buf_pos = 64
}

///|
/// Mixes fresh `entropy` with the current DRBG state using SHA-256 to derive a
/// new 256-bit key and resets the counter and buffer.
pub fn Drbg::reseed(self : Drbg, entropy : Bytes) -> Unit {
  let state_bytes = FixedArray::make(52, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    write_le_u32(state_bytes, i * 4, self.key[i])
  }
  write_le_u32(state_bytes, 32, self.counter)
  write_le_u32(state_bytes, 36, self.nonce[0])
  write_le_u32(state_bytes, 40, self.nonce[1])
  write_le_u32(state_bytes, 44, self.nonce[2])
  write_le_u32(state_bytes, 48, self.buf_pos.reinterpret_as_uint())
  let new_key_bytes = sha256_concat([Bytes::from_array(state_bytes), entropy])
  for i = 0; i < 8; i = i + 1 {
    self.key[i] = read_le_u32_bytes(new_key_bytes, i * 4)
  }
  self.counter = 0U
  self.nonce[0] = 0U
  self.nonce[1] = 0U
  self.nonce[2] = 0U
  zeroize_bytes(self.buf)
  zeroize_bytes(state_bytes)
  self.buf_pos = 64
}

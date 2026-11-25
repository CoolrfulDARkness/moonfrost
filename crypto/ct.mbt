///|
/// Constant-time primitives and memory zeroization (pure MoonBit, zero FFI).

///|
/// Internal sink used to prevent dead-store elimination of zeroization loops.
/// Only ever receives bitwise OR of already-zeroed buffers (always 0).
let zeroize_sink : FixedArray[UInt64] = FixedArray::make(1, 0UL)

///|
/// Converts the least significant bit of `bit` (0 or 1) into an all-zero
/// (`0UL`) or all-one (`0xffffffffffffffffUL`) 64-bit mask without branches.
pub fn ct_mask_from_bit(bit : UInt64) -> UInt64 {
  0UL - (bit & 1UL)
}

///|
/// Returns `0xffffffffffffffffUL` if `x == 0UL`, or `0UL` otherwise,
/// using branchless bitwise arithmetic.
pub fn ct_is_zero_u64(x : UInt64) -> UInt64 {
  let non_zero_bit = (x | (0UL - x)) >> 63
  0UL - (non_zero_bit ^ 1UL)
}

///|
/// Returns `0xffffffffffffffffUL` if `a == b`, or `0UL` otherwise,
/// using branchless bitwise arithmetic.
pub fn ct_eq_u64(a : UInt64, b : UInt64) -> UInt64 {
  ct_is_zero_u64(a ^ b)
}

///|
/// Constant-time select between `a` and `b` using a full-word `mask`.
/// Returns `a` when `mask == 0xffffffffffffffffUL` and `b` when `mask == 0UL`.
pub fn ct_select_u64(mask : UInt64, a : UInt64, b : UInt64) -> UInt64 {
  b ^ (mask & (a ^ b))
}

///|
/// Constant-time select between `a` and `b` using a full-word 32-bit `mask`.
/// Returns `a` when `mask == 0xffffffffU` and `b` when `mask == 0U`.
pub fn ct_select_u32(mask : UInt32, a : UInt32, b : UInt32) -> UInt32 {
  b ^ (mask & (a ^ b))
}

///|
/// Constant-time select between bytes `a` and `b` using `mask`.
/// Returns `a` when `mask` has its low byte all-1s (`0xffffffffU` or `0xffU`)
/// and `b` when `mask == 0U`.
pub fn ct_select_byte(mask : UInt32, a : Byte, b : Byte) -> Byte {
  let av = a.to_uint()
  let bv = b.to_uint()
  (bv ^ (mask & 0xffU & (av ^ bv))).to_byte()
}

///|
/// Constant-time equality comparison over two `Bytes` values.
/// Returns `false` immediately only if lengths differ; otherwise inspects
/// every byte without data-dependent branches.
pub fn ct_eq_bytes(a : Bytes, b : Bytes) -> Bool {
  let len = a.length()
  if len != b.length() {
    return false
  }
  let mut diff = 0U
  for i = 0; i < len; i = i + 1 {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  ct_is_zero_u64(diff.to_uint64()) != 0UL
}

///|
/// Constant-time equality comparison over two `FixedArray[Byte]` buffers.
/// Returns `false` immediately only if lengths differ; otherwise inspects
/// every byte without data-dependent branches.
pub fn ct_eq_fixed_bytes(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  let len = a.length()
  if len != b.length() {
    return false
  }
  let mut diff = 0U
  for i = 0; i < len; i = i + 1 {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  ct_is_zero_u64(diff.to_uint64()) != 0UL
}

///|
/// Overwrites every element of `buf` with zero bytes.
pub fn zeroize_bytes(buf : FixedArray[Byte]) -> Unit {
  let len = buf.length()
  for i = 0; i < len; i = i + 1 {
    buf[i] = b'\x00'
  }
  let mut acc = 0UL
  for i = 0; i < len; i = i + 1 {
    acc = acc | buf[i].to_uint64()
  }
  zeroize_sink[0] = zeroize_sink[0] ^ acc
}

///|
/// Overwrites every element of `buf` with `0U` (package-internal helper).
fn zeroize_u32(buf : FixedArray[UInt32]) -> Unit {
  let len = buf.length()
  for i = 0; i < len; i = i + 1 {
    buf[i] = 0U
  }
  let mut acc = 0UL
  for i = 0; i < len; i = i + 1 {
    acc = acc | buf[i].to_uint64()
  }
  zeroize_sink[0] = zeroize_sink[0] ^ acc
}

///|
/// Overwrites every element of `buf` with `0UL`.
pub fn zeroize_u64(buf : FixedArray[UInt64]) -> Unit {
  let len = buf.length()
  for i = 0; i < len; i = i + 1 {
    buf[i] = 0UL
  }
  let mut acc = 0UL
  for i = 0; i < len; i = i + 1 {
    acc = acc | buf[i]
  }
  zeroize_sink[0] = zeroize_sink[0] ^ acc
}

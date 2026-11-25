///|
/// RFC 9380 Section 5.3.1 expand_message_xmd with SHA-256
/// (b_in_bytes = 32, s_in_bytes = 64).

///|
fn xor_bytes_32(a : Bytes, b : Bytes) -> Bytes {
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = (a[i].to_uint() ^ b[i].to_uint()).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Implements `expand_message_xmd(msg, DST, len_in_bytes)` per RFC 9380 §5.3.1
/// using SHA-256 (`b_in_bytes = 32`, `s_in_bytes = 64`).
/// Rejects `len_in_bytes < 0`, `len_in_bytes > 65535`, `dst.length() > 255`,
/// or `ell = ceil(len_in_bytes / 32) > 255`.
pub fn expand_message_xmd_sha256(
  msg : Bytes,
  dst : Bytes,
  len_in_bytes : Int32,
) -> Result[Bytes, String] {
  if len_in_bytes < 0 || len_in_bytes > 65535 {
    return Err("expand_message_xmd_sha256: invalid len_in_bytes")
  }
  let dst_len = dst.length()
  if dst_len > 255 {
    return Err("expand_message_xmd_sha256: DST length exceeds 255 bytes")
  }
  let ell = if len_in_bytes == 0 { 0 } else { (len_in_bytes + 31) / 32 }
  if ell > 255 {
    return Err("expand_message_xmd_sha256: ell exceeds 255")
  }
  if len_in_bytes == 0 {
    return Ok(Bytes::make(0, b'\x00'))
  }
  // Step 3: DST_prime = DST || I2OSP(len(DST), 1)
  let dst_len_byte = Bytes::from_array([dst_len.to_byte()])
  let dst_prime = concat_bytes([dst, dst_len_byte])
  // Step 4: Z_pad = I2OSP(0, 64)
  let z_pad = Bytes::make(64, b'\x00')
  // Step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
  let l_i_b_str = Bytes::from_array([
    ((len_in_bytes >> 8) & 0xff).to_byte(),
    (len_in_bytes & 0xff).to_byte(),
  ])
  let zero_byte = Bytes::from_array([b'\x00'])
  // Step 6-7: b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
  let b0 = sha256_concat([z_pad, msg, l_i_b_str, zero_byte, dst_prime])
  // Step 8: b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  let mut b_prev = sha256_concat([b0, Bytes::from_array([b'\x01']), dst_prime])
  let out = FixedArray::make(len_in_bytes, b'\x00')
  let mut written = 0
  let first_copy = if len_in_bytes < 32 { len_in_bytes } else { 32 }
  for j = 0; j < first_copy; j = j + 1 {
    out[j] = b_prev[j]
  }
  written = first_copy
  // Step 9-10: for i in (2, ..., ell):
  //   b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
  for i = 2; i <= ell; i = i + 1 {
    let xored = xor_bytes_32(b0, b_prev)
    let b_i = sha256_concat([xored, Bytes::from_array([i.to_byte()]), dst_prime])
    let remain = len_in_bytes - written
    let to_copy = if remain < 32 { remain } else { 32 }
    for j = 0; j < to_copy; j = j + 1 {
      out[written + j] = b_i[j]
    }
    written = written + to_copy
    b_prev = b_i
  }
  Ok(Bytes::from_array(out))
}

///|
/// Hex encoding/decoding and byte-string utility helpers.

///|
fn nibble_to_hex_char(n : Int32) -> Char {
  if n < 10 {
    Int32::unsafe_to_char(48 + n)
  } else {
    Int32::unsafe_to_char(87 + n)
  }
}

///|
fn hex_char_to_nibble(c : Int32) -> Int32? {
  if c >= 48 && c <= 57 {
    Some(c - 48)
  } else if c >= 97 && c <= 102 {
    Some(c - 87)
  } else if c >= 65 && c <= 70 {
    Some(c - 55)
  } else {
    None
  }
}

///|
/// Encodes `data` into a lowercase hexadecimal `String`.
pub fn bytes_to_hex(data : Bytes) -> String {
  let len = data.length()
  let sb = StringBuilder(capacity=len * 2)
  for i = 0; i < len; i = i + 1 {
    let b = data[i].to_int()
    sb.write_char(nibble_to_hex_char((b >> 4) & 0x0f))
    sb.write_char(nibble_to_hex_char(b & 0x0f))
  }
  sb.to_string()
}

///|
/// Strictly decodes a hexadecimal `String` into `Bytes`.
/// Rejects odd-length strings and any non-hexadecimal character.
pub fn hex_to_bytes(hex : String) -> Result[Bytes, String] {
  let len = hex.length()
  if (len & 1) != 0 {
    return Err("hex_to_bytes: odd hex string length")
  }
  let out_len = len / 2
  let out = FixedArray::make(out_len, b'\x00')
  for i = 0; i < out_len; i = i + 1 {
    let hi_code = hex[i * 2].to_int()
    let lo_code = hex[i * 2 + 1].to_int()
    let hi = match hex_char_to_nibble(hi_code) {
      Some(v) => v
      None => return Err("hex_to_bytes: invalid hex character")
    }
    let lo = match hex_char_to_nibble(lo_code) {
      Some(v) => v
      None => return Err("hex_to_bytes: invalid hex character")
    }
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Ok(Bytes::from_array(out))
}

///|
/// Converts an ASCII `String` into `Bytes` by taking the low byte of each
/// code unit.
pub fn ascii_bytes(s : String) -> Bytes {
  let len = s.length()
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = (s[i].to_int() & 0xff).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Concatenates an `Array[Bytes]` into a single `Bytes`.
pub fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let part = parts[i]
    let plen = part.length()
    for j = 0; j < plen; j = j + 1 {
      out[offset + j] = part[j]
    }
    offset = offset + plen
  }
  Bytes::from_array(out)
}

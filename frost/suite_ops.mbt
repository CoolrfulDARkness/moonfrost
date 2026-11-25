///|
/// Generic ciphersuite descriptor encapsulating prime-order group arithmetic,
/// canonical serialization, and domain-separated hash functions (H1-H5, H_dkg)
/// as specified in IETF RFC 9591 §3 and §6.

///|
pub(all) struct SuiteOps[S, E] {
  context_string : String
  ne : Int32
  ns : Int32
  wide_bytes_len : Int32
  scalar_zero : () -> S
  scalar_one : () -> S
  scalar_from_u32 : (UInt32) -> S
  scalar_add : (S, S) -> S
  scalar_sub : (S, S) -> S
  scalar_mul : (S, S) -> S
  scalar_neg : (S) -> S
  scalar_invert : (S) -> Result[S, String]
  scalar_is_zero : (S) -> Bool
  scalar_eq : (S, S) -> Bool
  scalar_compare : (S, S) -> Int32
  serialize_scalar : (S) -> Bytes
  deserialize_scalar : (Bytes) -> Result[S, String]
  scalar_from_wide_bytes : (Bytes) -> Result[S, String]
  element_identity : () -> E
  element_generator : () -> E
  element_add : (E, E) -> E
  element_sub : (E, E) -> E
  element_neg : (E) -> E
  element_is_identity : (E) -> Bool
  element_eq : (E, E) -> Bool
  scalar_mul_elem : (E, S) -> E
  scalar_base_mul : (S) -> E
  serialize_element : (E) -> Result[Bytes, String]
  deserialize_element : (Bytes) -> Result[E, String]
  h1 : (Bytes) -> S
  h2 : (Bytes) -> S
  h3 : (Bytes) -> S
  h4 : (Bytes) -> Bytes
  h5 : (Bytes) -> Bytes
  h_dkg : (Bytes) -> S
}

///|
fn[S, E] id_to_scalar(
  ops : SuiteOps[S, E],
  id : Int32,
) -> Result[S, FrostError] {
  if id <= 0 {
    return Err(FrostError::InvalidParticipantId(id))
  }
  Ok((ops.scalar_from_u32)(id.reinterpret_as_uint()))
}

///|
fn[S, E] serialize_element_checked(
  ops : SuiteOps[S, E],
  elem : E,
) -> Result[Bytes, FrostError] {
  if (ops.element_is_identity)(elem) {
    return Err(FrostError::IdentityElement)
  }
  match (ops.serialize_element)(elem) {
    Ok(b) => Ok(b)
    Err(e) => Err(FrostError::InvalidElement(e))
  }
}

///|
/// Sorts an array of participant IDs in ascending order and removes duplicates.
fn sort_unique_ids(ids : Array[Int32]) -> Array[Int32] {
  let out : Array[Int32] = []
  for i = 0; i < ids.length(); i = i + 1 {
    out.push(ids[i])
  }
  // Insertion sort (small participant lists, deterministic, zero external deps).
  for i = 1; i < out.length(); i = i + 1 {
    let key = out[i]
    let mut j = i - 1
    while j >= 0 && out[j] > key {
      out[j + 1] = out[j]
      j = j - 1
    }
    out[j + 1] = key
  }
  let dedup : Array[Int32] = []
  for i = 0; i < out.length(); i = i + 1 {
    if i == 0 || out[i] != out[i - 1] {
      dedup.push(out[i])
    }
  }
  dedup
}

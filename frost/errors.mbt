///|
/// Structured error types for the IETF RFC 9591 FROST threshold signature
/// protocol, Feldman VSS, and Pedersen DKG.

///|
#derive(Eq, Debug)
pub(all) enum FrostError {
  InvalidParameters(String)
  InvalidThreshold(String)
  InvalidParticipantId(Int32)
  DuplicateParticipant(Int32)
  UnsortedCommitments
  InsufficientParticipants(Int32, Int32)
  InvalidScalar(String)
  InvalidElement(String)
  IdentityElement
  NonceAlreadyUsed
  CommitmentMismatch(Int32)
  InvalidVssCommitment(String)
  InvalidDkgProof(Array[Int32])
  CheaterDetected(Array[Int32])
  InvalidSignature
  InvalidSignatureLength(Int32, Int32)
}

///|
fn write_int_array(logger : &Logger, ids : Array[Int32]) -> Unit {
  logger.write_string("[")
  for i = 0; i < ids.length(); i = i + 1 {
    if i > 0 {
      logger.write_string(", ")
    }
    logger.write_string(ids[i].to_string())
  }
  logger.write_string("]")
}

///|
pub impl Show for FrostError with fn output(self, logger) {
  match self {
    InvalidParameters(msg) => logger.write_string("InvalidParameters(\{msg})")
    InvalidThreshold(msg) => logger.write_string("InvalidThreshold(\{msg})")
    InvalidParticipantId(id) =>
      logger.write_string("InvalidParticipantId(\{id})")
    DuplicateParticipant(id) =>
      logger.write_string("DuplicateParticipant(\{id})")
    UnsortedCommitments => logger.write_string("UnsortedCommitments")
    InsufficientParticipants(got, req) =>
      logger.write_string("InsufficientParticipants(\{got}, \{req})")
    InvalidScalar(msg) => logger.write_string("InvalidScalar(\{msg})")
    InvalidElement(msg) => logger.write_string("InvalidElement(\{msg})")
    IdentityElement => logger.write_string("IdentityElement")
    NonceAlreadyUsed => logger.write_string("NonceAlreadyUsed")
    CommitmentMismatch(id) => logger.write_string("CommitmentMismatch(\{id})")
    InvalidVssCommitment(msg) =>
      logger.write_string("InvalidVssCommitment(\{msg})")
    InvalidDkgProof(ids) => {
      logger.write_string("InvalidDkgProof(")
      write_int_array(logger, ids)
      logger.write_string(")")
    }
    CheaterDetected(ids) => {
      logger.write_string("CheaterDetected(")
      write_int_array(logger, ids)
      logger.write_string(")")
    }
    InvalidSignature => logger.write_string("InvalidSignature")
    InvalidSignatureLength(got, expected) =>
      logger.write_string("InvalidSignatureLength(\{got}, \{expected})")
  }
}

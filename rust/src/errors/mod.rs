use std::io::{Error, ErrorKind};

pub fn err_deserialization() -> Error { Error::new(ErrorKind::Other, "Failed to deserialize") }

// verification errors
pub fn err_public_key_not_found() -> Error { Error::new(ErrorKind::Other, "No public key found for verification") }
pub fn err_proof_not_found() -> Error { Error::new(ErrorKind::Other, "No proof object sent for verification") }
pub fn err_proof_verification() -> Error { Error::new(ErrorKind::Other, "Proof verification failed") }

pub fn err_finalization() -> Error { Error::new(ErrorKind::Other, "Finalization failed") }
pub fn err_internal() -> Error { Error::new(ErrorKind::Other, "Internal error occurred") }
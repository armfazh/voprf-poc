use crypto::hkdf::{hkdf_extract,hkdf_expand};
use crypto::sha2::Sha512;
use crypto::digest::Digest;
use super::copy_into;

const SHA512_OUTPUT_BYTES_LENGTH: usize = 64;

/// A wrapper around the rust-crypto implementation of HKDF
///
/// TODO: Rewrite to use the ring implementation. There were some difficulties
/// around the way that ring does not give access to the raw bytes output by
/// these algorithms
pub struct Hkdf {}

impl Hkdf {
    // extract, works over vectors rather than slices
    pub fn extract(&self, seed: &[u8], secret: &[u8], out: &mut Vec<u8>) {
        if out.len() != SHA512_OUTPUT_BYTES_LENGTH {
            copy_into(&[0; SHA512_OUTPUT_BYTES_LENGTH], out);
        }
        hkdf_extract(Sha512::new(), &seed, &secret, out)
    }

    // expand, works over vectors rather than slices
    pub fn expand(&self, prk: &[u8], info: &[u8], out: &mut Vec<u8>) {
        if out.len() != SHA512_OUTPUT_BYTES_LENGTH {
            copy_into(&[0; SHA512_OUTPUT_BYTES_LENGTH], out);
        }
        hkdf_expand(Sha512::new(), &prk, &info, out)
    }
}
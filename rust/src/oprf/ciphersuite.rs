use hmac::{Hmac,Mac};
use digest::Digest;

// supported primitives
use sha2::Sha512;
use super::groups::PrimeOrderGroup;
use curve25519_dalek::ristretto::RistrettoPoint;
use super::super::utils::hkdf::Hkdf;
use super::super::utils::copy_into;

use std::io::Error;
use super::super::errors::err_finalization;

/// The Supported trait defines the PrimeOrderGroup<T,H> instantiations that are
/// currently supported by the VOPRF implementation. Currently, only
/// T=curve25519_dalek::ristretto::RistrettoPoint and H=sha2::Sha512 are
/// supported. This corresponds to an experimental ristretto255 ciphersuite that
/// is not defined in draft-irth-cfrg-voprf-02.
pub trait Supported {
    fn name(&self) -> String;
}

impl Supported for PrimeOrderGroup<RistrettoPoint,Sha512> {
    fn name(&self) -> String {
        String::from("ristretto255-SHA512-HKDF-ELL2-RO")
    }
}

// Returns the name of the primitive set if it is supported
fn get_name<S: Supported>(x: &S) -> String {
    x.name()
}

/// The Ciphersuite struct gives access to the core functionality provided by a
/// VOPRF ciphersuite (see:
/// https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-6). In essence,
/// this is the PrimeOrderGroup instantiation that is used, along with ancillary
/// functions for hashing and manipulating data associated the group that is
/// used.
///
/// TODO: explain more!
#[derive(Clone)]
pub struct Ciphersuite<T,H>
        where PrimeOrderGroup<T,H>: Clone {
    pub name: String,
    pub verifiable: bool,
    pub pog: PrimeOrderGroup<T,H>
}

impl<T,H> Ciphersuite<T,H>
        where PrimeOrderGroup<T,H>: Supported, T: Clone, H: Default
        + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone {
    // constructor for the ciphersuite
    pub fn new(pog: PrimeOrderGroup<T,H>, verifiable: bool) -> Ciphersuite<T,H> {
        let mut name = String::from("");
        match verifiable {
            true => name.push_str("VOPRF-"),
            false => name.push_str("OPRF-"),
        }
        name.push_str(&get_name(&pog));
        Ciphersuite {
            name: name,
            verifiable: verifiable,
            pog: pog
        }
    }

    // h1
    pub fn h1(&self, buf: &[u8]) -> T {
        (self.pog.encode_to_group)(buf)
    }

    // h2
    pub fn h2(&self, key: &[u8]) -> Result<Hmac<H>, Error> {
        match Hmac::<H>::new_varkey(key) {
            Ok(mac) => {
                return Ok(mac);
            },
            Err(_) => return Err(err_finalization())
        }
    }

    // hash_generic
    fn hash_generic(&self, inp: &[u8], out: &mut Vec<u8>) {
        let mut hash_fn = (self.pog.hash)();
        hash_fn.input(inp);
        let res = hash_fn.result().to_vec();
        copy_into(&res, out);
    }

    // h3
    pub fn h3(&self, inp: &[u8], out: &mut Vec<u8>) {
        self.hash_generic(inp, out)
    }

    // h4
    pub fn h4(&self, inp: &[u8], out: &mut Vec<u8>) {
        self.hash_generic(inp, out)
    }

    pub fn h5(&self) -> Hkdf {
        Hkdf{}
    }
}

#[cfg(test)]
mod tests {
    use super::{PrimeOrderGroup,Ciphersuite};

    #[test]
    fn ristretto_oprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), false);
        assert_eq!(ciph.name, String::from("OPRF-ristretto255-SHA512-HKDF-ELL2-RO"));
        assert_eq!(ciph.verifiable, false);
    }

    #[test]
    fn ristretto_voprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), true);
        assert_eq!(ciph.name, String::from("VOPRF-ristretto255-SHA512-HKDF-ELL2-RO"));
        assert_eq!(ciph.verifiable, true);
    }

    #[test]
    fn ristretto_h1() {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog.clone(), true);
        let ge = ciph.h1(&[0; 32]);
        assert_eq!((pog.is_valid)(&ge), true);
    }

    #[test]
    fn ristretto_h3_h4() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), true);
        let mut h3_res: Vec<u8> = Vec::new();
        let mut h4_res: Vec<u8> = Vec::new();
        ciph.h3(&[0; 32], &mut h3_res);
        ciph.h4(&[0; 32], &mut h4_res);
        // should be equal as both functions use the same hash
        assert_eq!(h3_res, h4_res);
    }

    // TODO: test vectors for HMAC and HKDF?
}
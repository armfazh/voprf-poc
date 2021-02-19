//! The `redox_ecc` module allows creating a `PrimeOrderGroup` object
//! using the NIST P-384, P-521 elliptic curves, and curve448 (in
//! Montgomery encoding).
//!
//! # Example
//!
//! ```
//! use voprf_rs::oprf::groups::PrimeOrderGroup;
//! let pog = PrimeOrderGroup::p384();
//! ```
//!
//! Also supports: `PrimeOrderGroup::p521();` and
//! `PrimeOrderGroup::c448();`
use super::super::super::utils::copy_into;
use super::{GroupID, PrimeOrderGroup};
use hkdf_sha512::Hkdf;

use h2c_rust_ref::{
    GetHashToCurve, CURVE448_XMDSHA512_ELL2_RO_, P256_XMDSHA256_SSWU_RO_, P384_XMDSHA512_SSWU_RO_,
    P521_XMDSHA512_SSWU_RO_,
};
use redox_ecc::ellipticcurve::{Decode, EllipticCurve, Encode};
use redox_ecc::field::Field;
use redox_ecc::instances::{GetCurve, CURVE448, P256, P384, P521};
use redox_ecc::ops::Serialize;

use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::{BigInt, BigUint, Sign};
use rand_core::OsRng;
use rand_core::RngCore;
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha512;

#[macro_use]
mod macros;

/// Calculated by performing (modulus_bits+7)/8
const P256_BYTE_LENGTH: usize = 32;
const P384_BYTE_LENGTH: usize = 48;
const P521_BYTE_LENGTH: usize = 66;
const C448_BYTE_LENGTH: usize = 56;
const CURVE_BITMASK: &[u8] = &[0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f];

/// blah
pub type WPoint = redox_ecc::weierstrass::Point;
/// blah
pub type MPoint = redox_ecc::montgomery::Point;

/// Instantiation of `PrimeOrderGroup` for NIST curves in Weierstrass
/// form
impl PrimeOrderGroup<WPoint, Sha256> {
    /// Returns an instance of PrimeOrderGroup that allows performing
    /// (V)OPRF operations using the prime-order group associated the
    /// NIST P-256 curve.
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::p256();
    /// ```
    pub fn p256() -> PrimeOrderGroup<WPoint, Sha256> {
        PrimeOrderGroup {
            group_id: GroupID::P256,
            generator: P256.get().get_generator(),
            byte_length: P256_BYTE_LENGTH,
            hash: || hash256!(),
            encode_to_group: |buf: &[u8], dst: &[u8]| {
                hash_to_curve!(P256_XMDSHA256_SSWU_RO_, buf, dst)
            },
            is_valid: |p: &WPoint| P256.get().is_on_curve(p),
            is_equal: |p1: &WPoint, p2: &WPoint| p1 == p2,
            add: |p1: &WPoint, p2: &WPoint| p1 + p2,
            scalar_mult: |p: &WPoint, r: &[u8]| {
                let r_sc = to_scalar!(&P256.get(), r);
                p * r_sc
            },
            inverse_mult: |p: &WPoint, r: &[u8]| {
                let curve = P256.get();
                let one_sc = to_scalar!(&curve, &vec![1]);
                let r_sc = to_scalar!(&curve, r);
                let inv_sc = &one_sc / &r_sc;
                p * inv_sc
            },
            serialize: |p: &WPoint, compress: bool, out: &mut Vec<u8>| {
                point_serialize!(p, compress, out)
            },
            deserialize: |buf: &[u8]| P256.get().decode(buf),
            random_element: || {
                let curve = P256.get();
                let byte_len = field_byte_length!(&curve);
                let mut alpha = vec![0; byte_len];
                fill_uniform_bytes!(&curve, &mut alpha);
                hash_to_curve!(P256_XMDSHA256_SSWU_RO_, &alpha, b"")
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                let curve = P256.get();
                let byte_len = field_byte_length!(&P256.get());
                let mut alpha = vec![0; byte_len];
                fill_uniform_bytes!(&curve, &mut alpha);
                copy_into(&alpha, out);
            },
            reduce_scalar: |r: &[u8], _: bool| to_scalar!(&P256.get(), r).to_bytes_be(),
            // DLEQ functions
            dleq_generate: |key: &[u8],
                            pub_key: &WPoint,
                            input: &WPoint,
                            eval: &WPoint|
             -> [Vec<u8>; 2] {
                let curve = P256.get();
                dleq_gen!(&curve, key, pub_key, input, eval, hash256!())
            },
            dleq_verify: |pub_key: &WPoint, input: &WPoint, eval: &WPoint, proof: &[Vec<u8>; 2]| {
                let curve = P256.get();
                dleq_vrf!(&curve, pub_key, input, eval, proof, hash256!())
            },
            batch_dleq_generate: |key: &[u8],
                                  pub_key: &WPoint,
                                  inputs: &[WPoint],
                                  evals: &[WPoint]|
             -> [Vec<u8>; 2] {
                let curve = P256.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash256!());
                dleq_gen!(&curve, key, pub_key, &comp_m, &comp_z, hash256!())
            },
            batch_dleq_verify: |pub_key: &WPoint,
                                inputs: &[WPoint],
                                evals: &[WPoint],
                                proof: &[Vec<u8>; 2]| {
                let curve = P256.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash256!());
                dleq_vrf!(&curve, pub_key, &comp_m, &comp_z, proof, hash256!())
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8],
                                  pub_key: &WPoint,
                                  input: &WPoint,
                                  eval: &WPoint,
                                  fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = P256.get();
                fixed_dleq_gen!(&curve, key, pub_key, input, eval, fixed_scalar, hash256!())
            },
            fixed_batch_dleq_generate: |key: &[u8],
                                        pub_key: &WPoint,
                                        inputs: &[WPoint],
                                        evals: &[WPoint],
                                        fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = P256.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash256!());
                fixed_dleq_gen!(
                    &curve,
                    key,
                    pub_key,
                    &comp_m,
                    &comp_z,
                    fixed_scalar,
                    hash256!()
                )
            },
        }
    }
}

/// Instantiation of `PrimeOrderGroup` for NIST curves in Weierstrass
/// form
impl PrimeOrderGroup<WPoint, Sha512> {
    /// Returns an instance of PrimeOrderGroup that allows performing
    /// (V)OPRF operations using the prime-order group associated the
    /// NIST P-384 curve.
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::p384();
    /// ```
    pub fn p384() -> PrimeOrderGroup<WPoint, Sha512> {
        PrimeOrderGroup {
            group_id: GroupID::P384,
            generator: P384.get().get_generator(),
            byte_length: P384_BYTE_LENGTH,
            hash: || hash512!(),
            encode_to_group: |buf: &[u8], dst: &[u8]| {
                hash_to_curve!(P384_XMDSHA512_SSWU_RO_, buf, dst)
            },
            is_valid: |p: &WPoint| P384.get().is_on_curve(p),
            is_equal: |p1: &WPoint, p2: &WPoint| p1 == p2,
            add: |p1: &WPoint, p2: &WPoint| p1 + p2,
            scalar_mult: |p: &WPoint, r: &[u8]| {
                let r_sc = to_scalar!(&P384.get(), r);
                p * r_sc
            },
            inverse_mult: |p: &WPoint, r: &[u8]| {
                let curve = P384.get();
                let one_sc = to_scalar!(&curve, &vec![1]);
                let r_sc = to_scalar!(&curve, r);
                let inv_sc = &one_sc / &r_sc;
                p * inv_sc
            },
            serialize: |p: &WPoint, compress: bool, out: &mut Vec<u8>| {
                point_serialize!(p, compress, out)
            },
            deserialize: |buf: &[u8]| P384.get().decode(buf),
            random_element: || {
                let curve = P384.get();
                let byte_len = field_byte_length!(&curve);
                let mut alpha = vec![0; byte_len];
                fill_uniform_bytes!(&curve, &mut alpha);
                hash_to_curve!(P384_XMDSHA512_SSWU_RO_, &alpha, b"")
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                let curve = P384.get();
                let byte_len = field_byte_length!(&P384.get());
                let mut alpha = vec![0; byte_len];
                fill_uniform_bytes!(&curve, &mut alpha);
                copy_into(&alpha, out);
            },
            reduce_scalar: |r: &[u8], _: bool| to_scalar!(&P384.get(), r).to_bytes_be(),
            // DLEQ functions
            dleq_generate: |key: &[u8],
                            pub_key: &WPoint,
                            input: &WPoint,
                            eval: &WPoint|
             -> [Vec<u8>; 2] {
                let curve = P384.get();
                dleq_gen!(&curve, key, pub_key, input, eval, hash512!())
            },
            dleq_verify: |pub_key: &WPoint, input: &WPoint, eval: &WPoint, proof: &[Vec<u8>; 2]| {
                let curve = P384.get();
                dleq_vrf!(&curve, pub_key, input, eval, proof, hash512!())
            },
            batch_dleq_generate: |key: &[u8],
                                  pub_key: &WPoint,
                                  inputs: &[WPoint],
                                  evals: &[WPoint]|
             -> [Vec<u8>; 2] {
                let curve = P384.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                dleq_gen!(&curve, key, pub_key, &comp_m, &comp_z, hash512!())
            },
            batch_dleq_verify: |pub_key: &WPoint,
                                inputs: &[WPoint],
                                evals: &[WPoint],
                                proof: &[Vec<u8>; 2]| {
                let curve = P384.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                dleq_vrf!(&curve, pub_key, &comp_m, &comp_z, proof, hash512!())
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8],
                                  pub_key: &WPoint,
                                  input: &WPoint,
                                  eval: &WPoint,
                                  fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = P384.get();
                fixed_dleq_gen!(&curve, key, pub_key, input, eval, fixed_scalar, hash512!())
            },
            fixed_batch_dleq_generate: |key: &[u8],
                                        pub_key: &WPoint,
                                        inputs: &[WPoint],
                                        evals: &[WPoint],
                                        fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = P384.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                fixed_dleq_gen!(
                    &curve,
                    key,
                    pub_key,
                    &comp_m,
                    &comp_z,
                    fixed_scalar,
                    hash512!()
                )
            },
        }
    }
    /// Returns an instance of PrimeOrderGroup that allows performing
    /// (V)OPRF operations using the prime-order group associated the
    /// NIST P-521 curve.
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::p521();
    /// ```
    pub fn p521() -> PrimeOrderGroup<WPoint, Sha512> {
        PrimeOrderGroup {
            group_id: GroupID::P521,
            generator: P521.get().get_generator(),
            byte_length: P521_BYTE_LENGTH,
            hash: || hash512!(),
            encode_to_group: |buf: &[u8], dst: &[u8]| {
                hash_to_curve!(P521_XMDSHA512_SSWU_RO_, buf, dst)
            },
            is_valid: |p: &WPoint| P521.get().is_on_curve(p),
            is_equal: |p1: &WPoint, p2: &WPoint| p1 == p2,
            add: |p1: &WPoint, p2: &WPoint| p1 + p2,
            scalar_mult: |p: &WPoint, r: &[u8]| {
                let r_sc = to_scalar!(&P521.get(), r);
                p * r_sc
            },
            inverse_mult: |p: &WPoint, r: &[u8]| {
                let curve = P521.get();
                let one_sc = to_scalar!(&curve, &vec![1]);
                let r_sc = to_scalar!(&curve, r);
                let inv_sc = &one_sc / &r_sc;
                p * inv_sc
            },
            serialize: |p: &WPoint, compress: bool, out: &mut Vec<u8>| {
                point_serialize!(p, compress, out)
            },
            deserialize: |buf: &[u8]| P521.get().decode(buf),
            random_element: || {
                let curve = P521.get();
                let mut alpha = vec![0; P521_BYTE_LENGTH];
                fill_uniform_bytes!(&curve, &mut alpha);
                hash_to_curve!(P521_XMDSHA512_SSWU_RO_, &alpha, b"")
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                let curve = P521.get();
                let mut alpha = vec![0; P521_BYTE_LENGTH];
                fill_uniform_bytes!(&curve, &mut alpha);
                copy_into(&alpha, out);
            },
            reduce_scalar: |r: &[u8], _: bool| to_scalar!(&P521.get(), r).to_bytes_be(),
            // DLEQ functions
            dleq_generate: |key: &[u8],
                            pub_key: &WPoint,
                            input: &WPoint,
                            eval: &WPoint|
             -> [Vec<u8>; 2] {
                let curve = P521.get();
                dleq_gen!(&curve, key, pub_key, input, eval, hash512!())
            },
            dleq_verify: |pub_key: &WPoint, input: &WPoint, eval: &WPoint, proof: &[Vec<u8>; 2]| {
                let curve = P521.get();
                dleq_vrf!(&curve, pub_key, input, eval, proof, hash512!())
            },
            batch_dleq_generate: |key: &[u8],
                                  pub_key: &WPoint,
                                  inputs: &[WPoint],
                                  evals: &[WPoint]|
             -> [Vec<u8>; 2] {
                let curve = P521.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                dleq_gen!(&curve, key, pub_key, &comp_m, &comp_z, hash512!())
            },
            batch_dleq_verify: |pub_key: &WPoint,
                                inputs: &[WPoint],
                                evals: &[WPoint],
                                proof: &[Vec<u8>; 2]| {
                let curve = P521.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                dleq_vrf!(&curve, pub_key, &comp_m, &comp_z, proof, hash512!())
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8],
                                  pub_key: &WPoint,
                                  input: &WPoint,
                                  eval: &WPoint,
                                  fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = P521.get();
                fixed_dleq_gen!(&curve, key, pub_key, input, eval, fixed_scalar, hash512!())
            },
            fixed_batch_dleq_generate: |key: &[u8],
                                        pub_key: &WPoint,
                                        inputs: &[WPoint],
                                        evals: &[WPoint],
                                        fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = P521.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                fixed_dleq_gen!(
                    &curve,
                    key,
                    pub_key,
                    &comp_m,
                    &comp_z,
                    fixed_scalar,
                    hash512!()
                )
            },
        }
    }
}

/// Instantiation of `PrimeOrderGroup` for curve448 in Montgomery form
impl PrimeOrderGroup<MPoint, Sha512> {
    /// Returns an instance of PrimeOrderGroup that allows performing
    /// (V)OPRF operations using the prime-order group associated with
    /// curve448 in Montgomery format
    ///
    /// # Example
    ///
    /// ```
    /// use voprf_rs::oprf::groups::PrimeOrderGroup;
    /// let pog = PrimeOrderGroup::c448();
    /// ```
    pub fn c448() -> PrimeOrderGroup<MPoint, Sha512> {
        PrimeOrderGroup {
            group_id: GroupID::Curve448,
            generator: CURVE448.get().get_generator(),
            byte_length: C448_BYTE_LENGTH,
            hash: || hash512!(),
            encode_to_group: |buf: &[u8], dst: &[u8]| {
                hash_to_curve!(CURVE448_XMDSHA512_ELL2_RO_, buf, dst)
            },
            is_valid: |p: &MPoint| CURVE448.get().is_on_curve(p),
            is_equal: |p1: &MPoint, p2: &MPoint| p1 == p2,
            add: |p1: &MPoint, p2: &MPoint| p1 + p2,
            scalar_mult: |p: &MPoint, r: &[u8]| {
                let r_sc = to_scalar!(&CURVE448.get(), r);
                p * r_sc
            },
            inverse_mult: |p: &MPoint, r: &[u8]| {
                let curve = CURVE448.get();
                let one_sc = to_scalar!(&curve, &vec![1]);
                let r_sc = to_scalar!(&curve, r);
                let inv_sc = &one_sc / &r_sc;
                p * inv_sc
            },
            serialize: |p: &MPoint, compress: bool, out: &mut Vec<u8>| {
                point_serialize!(p, compress, out)
            },
            deserialize: |buf: &[u8]| CURVE448.get().decode(buf),
            random_element: || {
                let curve = CURVE448.get();
                let mut alpha = vec![0; C448_BYTE_LENGTH];
                fill_uniform_bytes!(&curve, &mut alpha);
                hash_to_curve!(CURVE448_XMDSHA512_ELL2_RO_, &alpha, b"")
            },
            uniform_bytes: |out: &mut Vec<u8>| {
                let curve = CURVE448.get();
                let mut alpha = vec![0; C448_BYTE_LENGTH];
                fill_uniform_bytes!(&curve, &mut alpha);
                copy_into(&alpha, out);
            },
            reduce_scalar: |r: &[u8], _: bool| to_scalar!(&CURVE448.get(), r).to_bytes_be(),
            // DLEQ functions
            dleq_generate: |key: &[u8],
                            pub_key: &MPoint,
                            input: &MPoint,
                            eval: &MPoint|
             -> [Vec<u8>; 2] {
                let curve = CURVE448.get();
                dleq_gen!(&curve, key, pub_key, input, eval, hash512!())
            },
            dleq_verify: |pub_key: &MPoint, input: &MPoint, eval: &MPoint, proof: &[Vec<u8>; 2]| {
                let curve = CURVE448.get();
                dleq_vrf!(&curve, pub_key, input, eval, proof, hash512!())
            },
            batch_dleq_generate: |key: &[u8],
                                  pub_key: &MPoint,
                                  inputs: &[MPoint],
                                  evals: &[MPoint]|
             -> [Vec<u8>; 2] {
                let curve = CURVE448.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                dleq_gen!(&curve, key, pub_key, &comp_m, &comp_z, hash512!())
            },
            batch_dleq_verify: |pub_key: &MPoint,
                                inputs: &[MPoint],
                                evals: &[MPoint],
                                proof: &[Vec<u8>; 2]| {
                let curve = CURVE448.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                dleq_vrf!(&curve, pub_key, &comp_m, &comp_z, proof, hash512!())
            },
            // DLEQ functions for testing
            fixed_dleq_generate: |key: &[u8],
                                  pub_key: &MPoint,
                                  input: &MPoint,
                                  eval: &MPoint,
                                  fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = CURVE448.get();
                fixed_dleq_gen!(&curve, key, pub_key, input, eval, fixed_scalar, hash512!())
            },
            fixed_batch_dleq_generate: |key: &[u8],
                                        pub_key: &MPoint,
                                        inputs: &[MPoint],
                                        evals: &[MPoint],
                                        fixed_scalar: &[u8]|
             -> [Vec<u8>; 2] {
                let curve = CURVE448.get();
                let [comp_m, comp_z] =
                    batch_compute_composities!(&curve, pub_key, inputs, evals, hash512!());
                fixed_dleq_gen!(
                    &curve,
                    key,
                    pub_key,
                    &comp_m,
                    &comp_z,
                    fixed_scalar,
                    hash512!()
                )
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redox_ecc::ellipticcurve::{EcPoint, EcScalar};

    #[test]
    fn weier_serialization() {
        serialization(&PrimeOrderGroup::p256());
        serialization(&PrimeOrderGroup::p384());
        serialization(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_serialization() {
        serialization(&PrimeOrderGroup::c448());
    }
    fn serialization<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        let p = (pog.random_element)();
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        let p_chk = (pog.deserialize)(&ser).expect("Failed to deserialize point");
        assert!((pog.is_equal)(&p, &p_chk), "{}", group_name(pog));
    }

    #[test]
    #[should_panic]
    fn weier_err_ser() {
        err_ser(&PrimeOrderGroup::p256());
        err_ser(&PrimeOrderGroup::p384());
        err_ser(&PrimeOrderGroup::p521());
    }
    #[test]
    #[should_panic]
    fn mont_err_ser() {
        err_ser(&PrimeOrderGroup::c448());
    }
    fn err_ser<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&(pog.random_element)(), true, &mut ser);
        // modify the buffer
        ser[0] = ser[0] + 2;
        ser[1] = ser[1] + 1;
        ser[2] = ser[2] + 1;
        ser[3] = ser[3] + 1;
        (pog.deserialize)(&ser).unwrap();
    }

    #[test]
    fn weier_point_mult() {
        weier_point_mult_core(&PrimeOrderGroup::p256());
        weier_point_mult_core(&PrimeOrderGroup::p384());
        weier_point_mult_core(&PrimeOrderGroup::p521());
    }

    fn weier_point_mult_core<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        let p = (pog.random_element)();
        let mut r1: Vec<u8> = Vec::new();
        let mut r2: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r1);
        (pog.uniform_bytes)(&mut r2);
        let r1_p = (pog.scalar_mult)(&p, &r1);
        let r2_p = (pog.scalar_mult)(&p, &r2);
        let add_p = (pog.add)(&r1_p, &r2_p);
        let curve = match pog.group_id {
            GroupID::P256 => P256.get(),
            GroupID::P384 => P384.get(),
            GroupID::P521 => P521.get(),
            _ => panic!("Unsupported group"),
        };
        let r1_sc = to_scalar!(&curve, &r1);
        let r2_sc = to_scalar!(&curve, &r2);
        let r1_r2_sc = &(r1_sc + r2_sc).to_bytes_be();
        let mult_p = (pog.scalar_mult)(&p, &r1_r2_sc);
        assert!((pog.is_equal)(&add_p, &mult_p), "{}", group_name(pog));
    }

    // re-using code as CURVE448 is a different type
    #[test]
    fn mont_point_mult() {
        let pog = PrimeOrderGroup::c448();
        let p = (pog.random_element)();
        let mut r1: Vec<u8> = Vec::new();
        let mut r2: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r1);
        (pog.uniform_bytes)(&mut r2);
        let r1_p = (pog.scalar_mult)(&p, &r1);
        let r2_p = (pog.scalar_mult)(&p, &r2);
        let add_p = (pog.add)(&r1_p, &r2_p);
        let curve = CURVE448.get();
        let r1_sc = to_scalar!(&curve, &r1);
        let r2_sc = to_scalar!(&curve, &r2);
        let r1_r2_sc = &(r1_sc + r2_sc).to_bytes_be();
        let mult_p = (pog.scalar_mult)(&p, &r1_r2_sc);
        assert!((pog.is_equal)(&add_p, &mult_p), "{}", group_name(&pog));
    }

    #[test]
    fn weier_encode_to_group() {
        encode_to_group(&PrimeOrderGroup::p256());
        encode_to_group(&PrimeOrderGroup::p384());
        encode_to_group(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_encode_to_group() {
        encode_to_group(&PrimeOrderGroup::c448());
    }
    fn encode_to_group<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        let msg: [u8; 32] = [0; 32];
        let dst: [u8; 32] = [0; 32];
        let p = (pog.encode_to_group)(&msg, &dst);
        let mut ser: Vec<u8> = Vec::new();
        (pog.serialize)(&p, true, &mut ser);
        // draft-irtf-cfrg-hash-to-curve-10
        let test_arr = match pog.group_id {
            GroupID::P256 => vec![
                3, 127, 34, 247, 143, 184, 135, 135, 93, 21, 207, 29, 239, 246, 252, 166, 21, 98,
                53, 5, 182, 1, 189, 134, 251, 184, 35, 232, 194, 59, 193, 209, 6,
            ],
            GroupID::P384 => vec![
                3, 70, 134, 9, 23, 254, 55, 161, 83, 115, 36, 106, 13, 231, 220, 128, 109, 8, 227,
                231, 222, 228, 235, 19, 43, 230, 249, 240, 107, 187, 41, 237, 67, 69, 14, 221, 72,
                232, 164, 154, 228, 29, 179, 115, 181, 123, 123, 254, 73,
            ],
            GroupID::P521 => vec![
                2, 1, 88, 90, 26, 37, 128, 83, 27, 94, 84, 24, 29, 40, 125, 81, 246, 191, 127, 172,
                58, 46, 219, 155, 242, 19, 85, 168, 30, 12, 238, 202, 141, 49, 154, 100, 223, 81,
                122, 187, 83, 157, 171, 90, 89, 99, 121, 82, 147, 36, 208, 211, 213, 254, 63, 44,
                99, 193, 162, 206, 173, 202, 222, 143, 212, 82, 9,
            ],
            GroupID::Curve448 => vec![
                3, 198, 203, 123, 135, 231, 217, 40, 54, 146, 149, 178, 76, 239, 36, 141, 252, 72,
                183, 247, 90, 94, 46, 35, 165, 228, 3, 141, 124, 30, 176, 68, 98, 22, 182, 81, 28,
                246, 1, 193, 220, 244, 36, 228, 160, 105, 136, 55, 135, 108, 245, 91, 62, 197, 134,
                79, 167,
            ],
            _ => panic!("Unsupported group"),
        };
        assert_eq!(ser, test_arr, "{}", group_name(&pog))
    }

    #[test]
    fn weier_rand_bytes() {
        rand_bytes(&PrimeOrderGroup::p256());
        rand_bytes(&PrimeOrderGroup::p384());
        rand_bytes(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_rand_bytes() {
        rand_bytes(&PrimeOrderGroup::c448());
    }
    fn rand_bytes<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        assert_eq!(r.len(), pog.byte_length, "{}", group_name(&pog));
        let fixed = match pog.group_id {
            GroupID::P256 => p256_convert_slice_to_fixed(&r),
            GroupID::P384 => p384_convert_slice_to_fixed(&r),
            GroupID::P521 => p521_convert_slice_to_fixed(&r),
            GroupID::Curve448 => c448_convert_slice_to_fixed(&r),
            _ => panic!("Incorrect byte length specified"),
        };
        assert_eq!(fixed.len(), pog.byte_length, "{}", group_name(&pog));
        for i in 0..pog.byte_length {
            assert_eq!(r[i], fixed[i], "{}", group_name(&pog));
        }
    }

    #[test]
    fn weier_inverse_mult() {
        inverse_mult(&PrimeOrderGroup::p256());
        inverse_mult(&PrimeOrderGroup::p384());
        inverse_mult(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_inverse_mult() {
        inverse_mult(&PrimeOrderGroup::c448());
    }
    fn inverse_mult<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        let mut r: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut r);
        let p = (pog.random_element)();
        let r_p = (pog.scalar_mult)(&p, &r);
        let inv_r_p = (pog.inverse_mult)(&r_p, &r);
        assert!((pog.is_equal)(&inv_r_p, &p), "{}", group_name(&pog));
    }

    #[test]
    fn weier_dleq() {
        dleq(&PrimeOrderGroup::p256());
        dleq(&PrimeOrderGroup::p384());
        dleq(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_dleq() {
        dleq(&PrimeOrderGroup::c448());
    }
    fn dleq<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);
        let m = (pog.random_element)();
        let z = (pog.scalar_mult)(&m, &key);

        // generate proof
        let proof = (pog.dleq_generate)(&key, &pub_key, &m, &z);
        assert_eq!(proof.len(), 2, "{}", group_name(&pog));

        // verify proof
        assert!(
            (pog.dleq_verify)(&pub_key, &m, &z, &proof),
            "{}",
            group_name(&pog)
        );
    }

    #[test]
    fn weier_dleq_batch() {
        dleq_batch(&PrimeOrderGroup::p256());
        dleq_batch(&PrimeOrderGroup::p384());
        dleq_batch(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_dleq_batch() {
        dleq_batch(&PrimeOrderGroup::c448());
    }
    fn dleq_batch<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for i in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(&inputs[i], &key));
        }

        // generate proof
        let proof = (pog.batch_dleq_generate)(&key, &pub_key, &inputs, &evals);
        assert_eq!(proof.len(), 2, "{}", group_name(&pog));

        // verify proof
        assert!(
            (pog.batch_dleq_verify)(&pub_key, &inputs, &evals, &proof),
            "{}",
            group_name(&pog)
        );
    }

    #[test]
    fn weier_fail_dleq() {
        fail_dleq(&PrimeOrderGroup::p256());
        fail_dleq(&PrimeOrderGroup::p384());
        fail_dleq(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_fail_dleq() {
        fail_dleq(&PrimeOrderGroup::c448());
    }
    fn fail_dleq<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        // mimic oprf operations
        let mut key_1: Vec<u8> = Vec::new();
        let mut key_2: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key_1);
        (pog.uniform_bytes)(&mut key_2);
        let pub_key_1 = (pog.scalar_mult)(&pog.generator, &key_1);
        let pub_key_2 = (pog.scalar_mult)(&pog.generator, &key_2);
        let m = (pog.random_element)();
        let z_1 = (pog.scalar_mult)(&m, &key_1);
        let z_2 = (pog.scalar_mult)(&m, &key_2);

        // generate proof
        let proof = (pog.dleq_generate)(&key_1, &pub_key_1, &m, &z_2);
        assert_eq!(proof.len(), 2, "{}", group_name(&pog));

        // verify proof
        assert!(
            !(pog.dleq_verify)(&pub_key_1, &m, &z_2, &proof),
            "{}",
            group_name(&pog)
        );

        // generate proof
        let proof = (pog.dleq_generate)(&key_1, &pub_key_2, &m, &z_1);
        assert_eq!(proof.len(), 2, "{}", group_name(&pog));

        // verify proof
        assert!(
            !(pog.dleq_verify)(&pub_key_2, &m, &z_1, &proof),
            "{}",
            group_name(&pog)
        );
    }

    #[test]
    fn weier_fail_dleq_batch_bad_batch() {
        fail_dleq_batch_bad_batch(&PrimeOrderGroup::p256());
        fail_dleq_batch_bad_batch(&PrimeOrderGroup::p384());
        fail_dleq_batch_bad_batch(&PrimeOrderGroup::p521());
    }
    #[test]
    fn mont_fail_dleq_batch_bad_batch() {
        fail_dleq_batch_bad_batch(&PrimeOrderGroup::c448());
    }
    fn fail_dleq_batch_bad_batch<S, T, H>(pog: &PrimeOrderGroup<T, H>)
    where
        S: EcScalar,
        T: EcPoint<S>,
    {
        // mimic oprf operations
        let mut key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut key);
        let pub_key = (pog.scalar_mult)(&pog.generator, &key);

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for i in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(&inputs[i], &key));
        }

        // modify a single point
        let mut bad_key: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut bad_key);
        evals[2] = (pog.scalar_mult)(&inputs[2], &bad_key);

        // generate proof
        let proof = (pog.batch_dleq_generate)(&key, &pub_key, &inputs, &evals);
        assert_eq!(proof.len(), 2, "{}", group_name(&pog));

        // verify proof
        assert!(
            !(pog.batch_dleq_verify)(&pub_key, &inputs, &evals, &proof),
            "{}",
            group_name(&pog)
        );
    }

    // converts a slice into an array of size P256_BYTE_LENGTH
    fn p256_convert_slice_to_fixed(x: &[u8]) -> Vec<u8> {
        let mut inp_bytes = [0; P256_BYTE_LENGTH];
        let random_bytes = &x[..inp_bytes.len()];
        inp_bytes.copy_from_slice(random_bytes);
        inp_bytes.to_vec()
    }

    // converts a slice into an array of size P384_BYTE_LENGTH
    fn p384_convert_slice_to_fixed(x: &[u8]) -> Vec<u8> {
        let mut inp_bytes = [0; P384_BYTE_LENGTH];
        let random_bytes = &x[..inp_bytes.len()];
        inp_bytes.copy_from_slice(random_bytes);
        inp_bytes.to_vec()
    }

    // converts a slice into an array of size P521_BYTE_LENGTH
    fn p521_convert_slice_to_fixed(x: &[u8]) -> Vec<u8> {
        let mut inp_bytes = [0; P521_BYTE_LENGTH];
        let random_bytes = &x[..inp_bytes.len()];
        inp_bytes.copy_from_slice(random_bytes);
        inp_bytes.to_vec()
    }

    // converts a slice into an array of size C448_BYTE_LENGTH
    fn c448_convert_slice_to_fixed(x: &[u8]) -> Vec<u8> {
        let mut inp_bytes = [0; C448_BYTE_LENGTH];
        let random_bytes = &x[..inp_bytes.len()];
        inp_bytes.copy_from_slice(random_bytes);
        inp_bytes.to_vec()
    }

    fn group_name<T, H>(pog: &PrimeOrderGroup<T, H>) -> String {
        match pog.group_id {
            GroupID::P256 => String::from("P256"),
            GroupID::P384 => String::from("P384"),
            GroupID::P521 => String::from("P521"),
            GroupID::Curve448 => String::from("curve448"),
            _ => panic!("Unsupported group"),
        }
    }
}

pub mod ristretto;

use std::io::Error;

/// The PrimeOrderGroup struct defines the behaviour expected from an additive
/// group with prime order instantiation. The template variable T corresponds to
/// the type of group elements that are used (for example, these could be points
/// taken from an elliptic curve), and H defines an accompanying hash function
/// implementation.
///
/// # Example functionality (using ristretto_255):
/// ```
/// use voprf_poc_rs::oprf::groups::PrimeOrderGroup;
/// // create group instantiation
/// let pog = PrimeOrderGroup::ristretto_255();
///
/// // fixed group generator
/// let g = pog.generator;
///
/// // sample random group elements
/// let re1 = (pog.random_element)();
/// let re2 = (pog.random_element)();
///
/// // hash bytes deterministically to an element of the group without revealing
/// // the discrete logarithm of the output element relative to the fixed
/// // generator.
/// let _ = (pog.encode_to_group)(b"some_input_bytes");
///
/// // perform additive group operation (returns the group element representing
/// // re1 + re2
/// let add = (pog.add)(&re1, &re2);
///
/// // sample random bytes from the field associated with the prime-order group
/// let mut x: Vec<u8> = Vec::new();
/// (pog.uniform_bytes)(&mut x);
///
/// // perform scalar multiplication (returns x * re1)
/// let mult = (pog.scalar_mult)(&re1, &x);
///
/// // perform scalar multiplication with the reciprocal of a scalar value
/// // (1/x)*x*re1
/// let inv_mult = (pog.inverse_mult)(&mult, &x);
///
/// // serialize and deserialize group elements
/// let mut ser: Vec<u8> = Vec::new();
/// (pog.serialize)(&re1, &mut ser);
/// let deser = match  (pog.deserialize)(&mut ser) {
///     Ok(p) => p,
///     Err(e) => panic!(e)
/// };
///
/// // check two points are equal
/// let b1 = (pog.is_equal)(&re1, &re2); // should return false
/// let b2 = (pog.is_equal)(&re1, &deser); // should return true
/// ```
///
/// Note that each instance of PrimeOrderGroup comes with its own instance of a
/// hash function that is defined by the type H. For example, hash function
/// evaluations can be accessed by running:
///
/// ```
/// use digest::Digest;
/// use voprf_poc_rs::oprf::groups::PrimeOrderGroup;
/// let pog = PrimeOrderGroup::ristretto_255();
/// let mut h = (pog.hash)();
/// h.input(b"some_data");
/// ```
///
/// Each PrimeOrderGroup also defines methods for computing DLEQ proofs (see:
/// https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02#section-5). The proofs
/// are dependent on scalar operations. These operations are implemeneted
/// differently depending on the type of scalars used.
///
/// DLEQ proof objects allow someone to generate proof objects that attest to
/// the fact that y = k*g and z = k*m share the same discrete logarithm k in
/// zero-knowledge, where g is the fixed group generator (i.e. without revealing
/// k). DLEQ proof generation and verification is as follows:
///
/// ```
/// use voprf_poc_rs::oprf::groups::PrimeOrderGroup;
/// let pog = PrimeOrderGroup::ristretto_255();
/// let m = (pog.random_element)();
///
/// // generate scalar value
/// let mut k: Vec<u8> = Vec::new();
/// (pog.uniform_bytes)(&mut k);
/// let y = (pog.scalar_mult)(&pog.generator, &k);
/// let z = (pog.scalar_mult)(&m, &k);
///
/// // generate proof object
/// let proof = (pog.dleq_generate)(&k, &y, &m, &z);
/// let b = (pog.dleq_verify)(&y, &m, &z, &proof); // should return true
/// ```
///
/// There are also "batch" methods that allow proving the same statement above
/// where m = vec![m_0, m_1, m_2, ...], z = vec![z_0, z_1, z_2] where z_i =
/// k*m_i for each i:
///
/// ```
/// use voprf_poc_rs::oprf::groups::PrimeOrderGroup;
/// let pog = PrimeOrderGroup::ristretto_255();
/// let mut k: Vec<u8> = Vec::new();
/// (pog.uniform_bytes)(&mut k);
/// let y = (pog.scalar_mult)(&pog.generator, &k);
///
/// let mut inputs = Vec::new();
/// let mut outs = Vec::new();
/// for _ in 0..5 {
///     let m = (pog.random_element)();
///     inputs.push(m);
///     outs.push((pog.scalar_mult)(&m, &k));
/// }
///
/// // generate batched proof object
/// let proof = (pog.batch_dleq_generate)(&k, &y, &inputs, &outs);
/// let b = (pog.batch_dleq_verify)(&y, &inputs, &outs, &proof); // should return true
/// ```
///
/// Notes:
/// -   the reason that we define the PrimeOrderGroup behaviour using a struct
///     rather than a trait is that I couldn't really find a good way of
///     defining a trait object that returned unsized types.
/// -   inversion of group elements is not implemented explicitly as it not
///     required for VOPRF functionality
#[derive(Clone)]
pub struct PrimeOrderGroup<T,H> {
    pub generator: T,
    pub byte_length: usize,
    pub hash: fn() -> H,
    pub encode_to_group: fn(&[u8]) -> T,
    pub is_valid: fn(&T) -> bool,
    pub is_equal: fn(&T, &T) -> bool,
    pub add: fn(&T, &T) -> T,
    pub scalar_mult: fn(&T, &[u8]) -> T,
    pub inverse_mult: fn(&T, &[u8]) -> T,
    pub random_element: fn() -> T,
    pub uniform_bytes: fn(&mut Vec<u8>),
    pub serialize: fn(&T, &mut Vec<u8>),
    pub deserialize: fn(&[u8]) -> Result<T, Error>,

    // DLEQ operations have to be defined with respect to the prime-order group
    // to allow for different scalar implementations
    pub dleq_generate: fn(&[u8], &T, &T, &T) -> [Vec<u8>; 2],
    pub dleq_verify: fn(&T, &T, &T, &[Vec<u8>; 2]) -> bool,
    pub batch_dleq_generate: fn(&[u8], &T, &[T], &[T]) -> [Vec<u8>; 2],
    pub batch_dleq_verify: fn(&T, &[T], &[T], &[Vec<u8>; 2]) -> bool,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
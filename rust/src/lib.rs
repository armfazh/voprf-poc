/// The `oprf` module provides access to the (V)OPRF API specified in
/// [draft-irtf-cfrg-voprf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/).
///
/// # Example
///
/// Provides a local end-to-end example of the (V)OPRF protocol interaction
/// between server and client.
///
/// ```
/// use voprf_rs::oprf::groups::PrimeOrderGroup;
/// use voprf_rs::oprf::{Server,Client};
/// use voprf_rs::oprf::ciphersuite::Ciphersuite;
/// use curve25519_dalek::ristretto::RistrettoPoint;
/// use sha2::Sha512;
///
/// // create Paticipant objects
/// let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
/// let ciph = Ciphersuite::<RistrettoPoint,Sha512>::new(pog.clone(), true);
/// let srv = Server::<RistrettoPoint,Sha512>::setup(ciph.clone());
/// let cli = match Client::<RistrettoPoint,Sha512>::setup(ciph.clone(), Some(srv.key.pub_key(&pog))) {
///     Ok(c) => c,
///     Err(e) => panic!(e),
/// };
///
/// // client generates and blinds a token
/// let mut x: Vec<u8> = Vec::new();
/// (pog.uniform_bytes)(&mut x);
/// let input_vec = cli.blind(&vec![x]);
///
/// // server evaluates PRF on single input
/// let eval = srv.eval(&vec![input_vec[0].elem]);
/// assert_eq!(eval.elems.len(), 1);
/// if let Some(d) = &eval.proof {
///     assert_eq!(d.len(), 2)
/// } else {
///     panic!("a proof should have been provided")
/// }
///
/// // client unblinds and finalizes the server response response
/// match cli.unblind(&input_vec, &eval) {
///     Ok(u) => {
///         let input_data = &input_vec[0].data;
///         // client finalization_check
///         let aux = b"auxiliary_data";
///         let out = match cli.finalize(&input_data, &eval.elems[0], aux) {
///             Ok(o) => o,
///             Err(e) => panic!(e)
///         };
///     },
///     Err(e) => panic!(e)
/// }
/// ```
pub mod oprf;

/// The `utils` module provides access to a small number of utility functions
/// for processing data, and performing generic cryptographic operations.
pub mod utils;

/// The `errors` module describes (exhaustively) the high-level error types that
/// occur during the (V)OPRF protocol.
pub mod errors;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

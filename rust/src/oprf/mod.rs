pub mod ciphersuite;
pub mod groups;

use groups::PrimeOrderGroup;
use ciphersuite::Ciphersuite;

use hmac::Mac;

use std::io::Error;
use super::errors::{err_internal,err_public_key_not_found,err_proof_not_found,err_proof_verification};

const OPRF_DST: &'static str = "oprf_derive_output";

/// The `SecretKey` struct provides a wrapper around a number of bytes of
/// varying length.
pub struct SecretKey(Vec<u8>);

/// The `PublicKey` object provides a wrapper around a type `T` that is defined
/// to be the type of group elements used in instantiating a group of the form
/// `PrimeOrderGroup<T,H>`.
#[derive(Clone)]
pub struct PublicKey<T>(T);

impl SecretKey {
    /// Constructor for `SecretKey<T,H>` for an underlying group instance of the
    /// form `PrimeOrderGroup<T,H>`.
    pub fn new<T,H>(pog: &PrimeOrderGroup<T,H>) -> Self {
        let mut buf: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut buf);
        SecretKey(buf)
    }

    /// Computes the corresponding `PublicKey<T>` object for a `SecretKey`
    /// object associated with `PrimeOrderGroup<T,H>`. Essentially computes
    /// `g*k` where `g` is the fixed generator of the group, and where `k` is
    /// the scaalr value of the secret key.
    pub fn pub_key<T,H>(&self, pog: &PrimeOrderGroup<T,H>) -> PublicKey<T>
            where T: Clone {
        PublicKey((pog.scalar_mult)(&pog.generator, &self.0))
    }
}

#[derive(Clone)]
pub struct Input<T> {
    data: Vec<u8>,
    elem: T,
    blind: Vec<u8>
}

#[derive(Clone)]
pub struct Evaluation<T>{
    elems: Vec<T>,
    proof: Option<[Vec<u8>; 2]>
}

// protocol participant
#[derive(Clone)]
pub struct Participant<T,H,K>
        where T: Clone, H: Clone {
    ciph: Ciphersuite<T,H>,
    key: K
}

type Server<T,H> = Participant<T,H,SecretKey>;

impl<T,H> Server<T,H>
        where T: Clone, H: Clone {
    pub fn setup(ciph: Ciphersuite<T,H>) -> Self {
        let pog = &ciph.pog.clone();
        Server{
            ciph: ciph,
            key: SecretKey::new(pog),
        }
    }

    pub fn eval(&self, input_elems: &[T]) -> Evaluation<T> {
        let mut eval_elems = Vec::new();
        let ciph = &self.ciph;
        let pog = &ciph.pog;
        let key = &self.key;

        // recover secret key value
        let sk = &key.0;
        for m in input_elems {
            eval_elems.push((pog.scalar_mult)(m, sk));
        }

        // generate proof if necessary
        let mut proof = None;
        if ciph.verifiable {
            let pk = key.pub_key(pog).0;
            proof = match input_elems.len() > 1 {
                true => Some((pog.batch_dleq_generate)(&sk, &pk, &input_elems, &eval_elems)),
                false => Some((pog.dleq_generate)(&sk, &pk, &input_elems[0], &eval_elems[0]))
            }
        }

        return Evaluation{
            elems: eval_elems,
            proof: proof,
        };
    }
}

type Client<T,H> = Participant<T,H,Option<PublicKey<T>>>;

impl<T,H> Client<T,H>
        where T: Clone, H: Clone + digest::BlockInput + digest::FixedOutput
        + digest::Input + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: ciphersuite::Supported {
    pub fn setup(ciph: Ciphersuite<T,H>, pub_key: Option<PublicKey<T>>) -> Result<Self, Error> {
        let pk_obj = None;
        // verifiable ciphersuites must have a public key set
        if ciph.verifiable {
            if let None = pub_key {
                return Err(err_public_key_not_found());
            }
        }
        Ok(Client{
            ciph: ciph,
            key: pk_obj
        })
    }

    // blind, TODO: update draft to allow blinding/unblinding multiple inputs at
    // once (maybe created batched alternatives?)
    pub fn blind(&self, inputs: &[Vec<u8>]) -> Vec<Input<T>> {
        let mut blinded_inputs: Vec<Input<T>> = Vec::new();
        for x in inputs {
            let ciph = &self.ciph;
            let pog = &ciph.pog;
            let mut r: Vec<u8> = Vec::new();
            (pog.uniform_bytes)(&mut r);
            let t = ciph.h1(&x);
            let p = (pog.scalar_mult)(&t, &r);
            blinded_inputs.push(Input{
                data: x.to_vec(),
                elem: p,
                blind: r
            });
        }
        blinded_inputs
    }

    // unblind, TODO: see above
    pub fn unblind(&self, inputs: &[Input<T>], eval: &Evaluation<T>) -> Result<Vec<T>, Error> {
        let ciph = &self.ciph;
        let pog = &ciph.pog;
        let eval_elems = &eval.elems;
        // check that the number of inputs is the same as the number of outputs
        assert_eq!(inputs.len(), eval_elems.len());
        // verify proof if necessary
        let mut proof_verification = Ok(false);
        if ciph.verifiable {
            // recover proof
            if let Some(d) = &eval.proof {
                if let Some(pk) = &self.key {
                    // get input group elements and verify proof
                    let verify_evals = eval_elems;
                    match inputs.len() > 1 {
                        true => {
                            let mut input_elems = Vec::new();
                            for input in inputs {
                                input_elems.push(input.elem.clone());
                            }
                            proof_verification = Ok((pog.batch_dleq_verify)(&pk.0, &input_elems, &verify_evals, &d));
                        },
                        false => {
                            proof_verification = Ok((pog.dleq_verify)(&pk.0, &inputs[0].elem, &verify_evals[0], &d));
                        }
                    };
                } else {
                    proof_verification = Err(err_proof_not_found());
                }
            } else {
                proof_verification = Err(err_public_key_not_found());
            }
        }
        let mut outs: Vec<T> = Vec::new();
        for i in 0..eval_elems.len() {
            let elem = &eval_elems[i];
            let blind = &inputs[i].blind;
            outs.push((pog.inverse_mult)(elem, blind));
        }

        if ciph.verifiable {
            if let Ok(b) = proof_verification {
                // if false, then the proof failed to verify
                if !b {
                    return Err(err_proof_verification());
                }
            }
        }
        Ok(outs)
    }

    // finalize
    pub fn finalize(&self, input_data: &[u8], elem: &T, aux: &[u8]) -> Result<Vec<u8>, Error> {
        let ciph = &self.ciph;
        let pog = &ciph.pog;

        // derive shared key
        match ciph.h2(&String::from(OPRF_DST).as_bytes()) {
            Ok(mut mac) => {
                mac.input(input_data);
                let mut ser: Vec<u8> = Vec::new();
                (pog.serialize)(&elem, &mut ser);
                mac.input(&ser);
                let dk = mac.result().code().to_vec();

                // derive output
                match ciph.h2(&dk) {
                    Ok(mut inner_mac) => {
                        inner_mac.input(&aux);
                        Ok(inner_mac.result().code().to_vec())
                    },
                    Err(_) => Err(err_internal())
                }
            },
            Err(_) => Err(err_internal())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::groups::PrimeOrderGroup;
    use super::{Client,Server,Ciphersuite,Input,Evaluation,PublicKey};
    use super::ciphersuite::Supported;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use sha2::Sha512;

    #[test]
    fn end_to_end_oprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        let ciph = Ciphersuite::<RistrettoPoint,Sha512>::new(pog.clone(), false);
        let srv = Server::<RistrettoPoint,Sha512>::setup(ciph.clone());
        let cli = match Client::<RistrettoPoint,Sha512>::setup(ciph.clone(), None) {
            Ok(c) => c,
            Err(e) => panic!(e),
        };

        // generate and blind a token
        let mut x: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut x);
        let input_vec = cli.blind(&vec![x]);

        // evaluate PRF on single input
        let eval = srv.eval(&vec![input_vec[0].elem]);
        assert_eq!(eval.elems.len(), 1);
        if let Some(_) = eval.proof {
            panic!("no proof should have been provided")
        }

        // unblind and check finalization
        unblind_and_check(srv, &cli, &ciph, input_vec, &eval);
    }

    #[test]
    fn end_to_end_voprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        let ciph = Ciphersuite::<RistrettoPoint,Sha512>::new(pog.clone(), true);
        let srv = Server::<RistrettoPoint,Sha512>::setup(ciph.clone());
        let cli = match Client::<RistrettoPoint,Sha512>::setup(ciph.clone(), Some(srv.key.pub_key(&pog))) {
            Ok(c) => c,
            Err(e) => panic!(e),
        };

        // generate and blind a token
        let mut x: Vec<u8> = Vec::new();
        (pog.uniform_bytes)(&mut x);
        let input_vec = cli.blind(&vec![x]);

        // evaluate PRF on single input
        let eval = srv.eval(&vec![input_vec[0].elem]);
        assert_eq!(eval.elems.len(), 1);
        if let Some(d) = &eval.proof {
            assert_eq!(d.len(), 2)
        } else {
            panic!("a proof should have been provided")
        }

        // unblind and check finalization
        unblind_and_check(srv, &cli, &ciph, input_vec, &eval);
    }

    #[test]
    fn end_to_end_batch_oprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        let ciph = Ciphersuite::<RistrettoPoint,Sha512>::new(pog.clone(), false);
        let srv = Server::<RistrettoPoint,Sha512>::setup(ciph.clone());
        let cli = match Client::<RistrettoPoint,Sha512>::setup(ciph.clone(), None) {
            Ok(c) => c,
            Err(e) => panic!(e),
        };

        // generate and blind a token
        let mut input_data_vec = Vec::new();
        let mut x: Vec<u8> = Vec::new();
        for _ in 0..5 {
            (pog.uniform_bytes)(&mut x);
            input_data_vec.push(x.clone());
        }
        let input_vec = cli.blind(&input_data_vec);

        // evaluate PRF on single input
        let mut input_elems = Vec::new();
        for input in &input_vec {
            input_elems.push(input.elem);
        }
        let eval = srv.eval(&input_elems);
        assert_eq!(eval.elems.len(), 5);
        if let Some(_) = eval.proof {
            panic!("no proof should have been provided")
        }

        // unblind and check finalization
        unblind_and_check(srv, &cli, &ciph, input_vec, &eval);
    }

    #[test]
    fn end_to_end_batch_voprf_ristretto() {
        let pog = PrimeOrderGroup::<RistrettoPoint,Sha512>::ristretto_255();
        let ciph = Ciphersuite::<RistrettoPoint,Sha512>::new(pog.clone(), true);
        let srv = Server::<RistrettoPoint,Sha512>::setup(ciph.clone());
        let cli = match Client::<RistrettoPoint,Sha512>::setup(ciph.clone(), Some(srv.key.pub_key(&pog))) {
            Ok(c) => c,
            Err(e) => panic!(e),
        };

        // generate and blind a token
        let mut input_data_vec = Vec::new();
        let mut x: Vec<u8> = Vec::new();
        for _ in 0..5 {
            (pog.uniform_bytes)(&mut x);
            input_data_vec.push(x.clone());
        }
        let input_vec = cli.blind(&input_data_vec);

        // evaluate PRF on single input
        let mut input_elems = Vec::new();
        for input in &input_vec {
            input_elems.push(input.elem);
        }
        let eval = srv.eval(&input_elems);
        assert_eq!(eval.elems.len(), 5);
        if let Some(d) = eval.proof.clone() {
            assert_eq!(d.len(), 2)
        } else {
            panic!("a proof should have been provided")
        }

        // unblind and check finalization
        unblind_and_check(srv, &cli, &ciph, input_vec, &eval);
    }

    fn unblind_and_check<T,H>(srv: Server<T,H>, cli: &Client<T,H>, ciph: &Ciphersuite<T,H>, input_vec: Vec<Input<T>>, eval: &Evaluation<T>)
            where Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
            + digest::BlockInput + digest::FixedOutput + digest::Input
            + digest::Reset + std::default::Default,
            PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
        // unblind server evaluation
        match cli.unblind(&input_vec, eval) {
            Ok(u) => {
                let sk = srv.key.0;
                for i in 0..input_vec.len() {
                    let input_data = &input_vec[i].data;
                    finalization_check(cli, &sk, ciph, input_data, &u[i]);
                }
            },
            Err(e) => panic!(e)
        }
    }

    fn finalization_check<T,H>(cli: &Client<T,H>, sk: &[u8], ciph: &Ciphersuite<T,H>, input_data: &[u8], evals: &T)
            where Input<T>: Clone, Evaluation<T>: Clone, T: Clone, H: Clone
            + digest::BlockInput + digest::FixedOutput + digest::Input
            + digest::Reset + std::default::Default,
            PrimeOrderGroup<T, H>: Supported, Client<T,H>: Clone {
        // finalize output
        let aux = b"auxiliary_data";
        let out = match cli.finalize(&input_data, &evals, aux) {
            Ok(o) => o,
            Err(e) => panic!(e)
        };

        // check output with server (without blinding)
        let ge = ciph.h1(&input_data);
        let chk_eval = (ciph.pog.scalar_mult)(&ge, &sk);
        let chk_out = match cli.finalize(&input_data, &chk_eval, aux) {
            Ok(o) => o,
            Err(e) => panic!(e)
        };

        // check that the outputs are consistent
        assert_eq!(out, chk_out);
    }
}
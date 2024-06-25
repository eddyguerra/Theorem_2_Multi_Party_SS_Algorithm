extern crate rand;
extern crate sha2;
extern crate curve25519_dalek;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
// Schnorr Signature
pub struct SchnorrSignature {
    pub gr: RistrettoPoint,
    pub s: Scalar,
}

impl fmt::Display for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?}, {:?})", self.gr.compress(), self.s)
    }
}

// Key generation for n parties
pub fn keygen(n: usize) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
    let mut csprng = OsRng;
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n {
        let mut sk_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let pk = RistrettoPoint::mul_base(&sk);
        sks.push(sk);
        pks.push(pk);
    }
    (sks, pks)
}

// Hash function
fn hash(data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result[..32]);
    Scalar::from_bytes_mod_order(hash_bytes)
}

// Signing process for n parties
pub fn sign(message: &str, sks: &[Scalar]) -> Vec<SchnorrSignature> {
    let mut csprng = OsRng;
    let mut rs = Vec::new();
    let mut grs = Vec::new();
    let mut commitments = Vec::new();

    // Step 1: Each participant generates random values r and their commitments
    for _ in sks {
        let mut r_bytes = [0u8; 32];
        csprng.fill_bytes(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order(r_bytes);
        let gr = RistrettoPoint::mul_base(&r);
        rs.push(r);
        grs.push(gr);
        commitments.push(hash(&gr.compress().as_bytes().to_vec()));
    }

    // Step 2: Each participant sends their decommitment
    for i in 0..sks.len() {
        println!("Party {} sends decommitment: {:?}", i + 1, grs[i]);
    }

    // Step 3: Each participant verifies the commitments of the other parties
    let mut all_passed = true;
    for i in 0..sks.len() {
        for j in 0..sks.len() {
            if i != j {
                let expected_commitment = hash(&grs[j].compress().as_bytes().to_vec());
                if commitments[j] == expected_commitment {
                    println!("Party {} verified commitment of party {} successfully", i + 1, j + 1);
                } else {
                    println!("Party {} failed to verify commitment of party {}", i + 1, j + 1);
                    all_passed = false;
                }
            }
        }
    }

    if !all_passed {
        panic!("Aborting due to failed commitment verification");
    }

    // Step 4: Aggregate commitments
    let mut aggregate_commitments = commitments[0];
    for i in 1..commitments.len() {
        aggregate_commitments += commitments[i];
    }

    // Step 5: Compute random challenge
    let aggregate_commitments_bytes = aggregate_commitments.to_bytes().to_vec();
    let message_bytes = message.as_bytes().to_vec();
    let c = hash(&[aggregate_commitments_bytes.as_slice(), message_bytes.as_slice()].concat());

    // Step 6: Each participant generates their partial signatures
    let mut signatures = Vec::new();
    for (i, sk) in sks.iter().enumerate() {
        let gr = grs[i];
        let s = rs[i] + c * sk;  // `c` is the aggregated challenge from above
        signatures.push(SchnorrSignature { gr, s });
    }

    signatures
}

fn main() {
    // Number of parties
    let n = 5;

    // Key generation
    let (sks, pks) = keygen(n);
    for i in 0..n {
        println!("Party {} - Secret Key: {:?}", i + 1, sks[i]);
        println!("Party {} - Public Key: {:?}", i + 1, pks[i]);
    }

    // Message
    let message = "how are you doing!";

    // Signing
    let signatures = sign(message, &sks);
    for (i, signature) in signatures.iter().enumerate() {
        println!("Party {} - Signature: {:?}", i + 1, signature);
    }
}

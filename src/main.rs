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
    for (i, _) in sks.iter().enumerate() {
        let mut r_bytes = [0u8; 32];
        csprng.fill_bytes(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order(r_bytes);
        let gr = RistrettoPoint::mul_base(&r);
        rs.push(r);
        grs.push(gr);
        commitments.push(hash(&gr.compress().as_bytes().to_vec()));
        println!("Party {} broadcasts commitment: {:?}", i + 1, commitments[i]);
    }

    // Step 2: Each participant sends their decommitment
    for i in 0..sks.len() {
        println!("Party {} broadcasts decommitment: {:?}", i + 1, grs[i]);
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

    // Step 4: Aggregate gr-values
    let mut aggregate_grs = grs[0];
    for i in 1..grs.len() {
        aggregate_grs += grs[i];
    }

    // Step 5: Compute random challenge
    let aggregate_grs_bytes = aggregate_grs.compress().as_bytes().to_vec();
    let message_bytes = message.as_bytes().to_vec();
    let c = hash(&[aggregate_grs_bytes.as_slice(), message_bytes.as_slice()].concat());

    // Step 6: Each participant generates their partial signatures
    let mut signatures = Vec::new();
    for (i, sk) in sks.iter().enumerate() {
        let gr = grs[i];
        let s = rs[i] + c * sk;  // `c` is the aggregated challenge from above
        signatures.push(SchnorrSignature { gr, s });
    }

    // Step 7: Verify each partial signature
    for (i, signature) in signatures.iter().enumerate() {
        let pk = RistrettoPoint::mul_base(&sks[i]);
        let is_valid = verify_partial_signature(message, &signature, &pk, &grs, &message_bytes);
        println!("Partial signature {} is valid: {}", i + 1, is_valid);
        if !is_valid {
            panic!("Aborting due to invalid partial signature");
        }
    }

    signatures
}

// Function to verify a partial signature
fn verify_partial_signature(_: &str, sig: &SchnorrSignature, pk: &RistrettoPoint, grs: &[RistrettoPoint], message_bytes: &[u8]) -> bool {
    let aggregate_grs = grs.iter().fold(RistrettoPoint::default(), |acc, gr| acc + *gr);
    let aggregate_grs_bytes = aggregate_grs.compress().as_bytes().to_vec();
    let c = hash(&[aggregate_grs_bytes.as_slice(), message_bytes].concat());
    let g_s = RistrettoPoint::mul_base(&sig.s);
    g_s == (sig.gr + c * pk)
}

// Function to aggregate signatures
fn aggregate_signatures(signatures: &[SchnorrSignature]) -> SchnorrSignature {
    let mut gr_agg = signatures[0].gr;
    let mut s_agg = signatures[0].s;


    for sig in &signatures[1..] {
        gr_agg += sig.gr;
        s_agg += sig.s;
    }

    SchnorrSignature { gr: gr_agg, s: s_agg }
}

// Function to aggregate public keys
fn aggregate_public_keys(pks: &[RistrettoPoint]) -> RistrettoPoint {
    let mut pk_agg = pks[0];
    for pk in &pks[1..] {
        pk_agg += pk;
    }
    pk_agg
}

// Function to verify aggregated signature
fn verify_aggregate_signature(message: &str, agg_sig: &SchnorrSignature, agg_pk: &RistrettoPoint) -> bool {
    let gr_bytes = agg_sig.gr.compress().as_bytes().to_vec();
    let message_bytes = message.as_bytes().to_vec();
    let c = hash(&[gr_bytes.as_slice(), message_bytes.as_slice()].concat());
    let g_s_agg = RistrettoPoint::mul_base(&agg_sig.s);
    g_s_agg == (agg_sig.gr + c * agg_pk)
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

    // Aggregate signatures and public keys
    let agg_sig = aggregate_signatures(&signatures);
    let agg_pk = aggregate_public_keys(&pks);

    println!("Aggregated Signature: {:?}", agg_sig);
    println!("Aggregated Public Key: {:?}", agg_pk);

    // Verify the aggregated signature
    let is_valid = verify_aggregate_signature(message, &agg_sig, &agg_pk);
    println!("Is the aggregated signature valid? {}", is_valid);
}

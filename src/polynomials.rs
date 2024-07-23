extern crate curve25519_dalek;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use winter_math::fields::f128::BaseElement;
use winter_math::FieldElement;

#[derive(Clone, Debug)]
pub struct PolynomialG {
    pub terms: Vec<RistrettoPoint>,
}

impl PolynomialG {
    // Initialize a polynomial with zero group elements
    pub fn zero() -> Self {
        Self { terms: vec![RistrettoPoint::identity()] }
    }

    // Add a single term
    pub fn add_term(&mut self, term: RistrettoPoint) {
        self.terms.push(term);
    }

    // Add two polynomials (term-wise)
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.terms.len().max(other.terms.len());
        let mut result_terms = vec![RistrettoPoint::identity(); max_len];

        for i in 0..self.terms.len() {
            result_terms[i] = result_terms[i] + self.terms[i];
        }

        for i in 0..other.terms.len() {
            result_terms[i] = result_terms[i] + other.terms[i];
        }

        Self { terms: result_terms }
    }

    // Multiply polynomial by a scalar
    pub fn mul_scalar(&self, scalar: Scalar) -> Self {
        let result_terms: Vec<RistrettoPoint> = self.terms.iter().map(|t| t * scalar).collect();
        Self { terms: result_terms }
    }
}

#[derive(Clone, Debug)]
pub struct PolynomialS {
    pub coeffs: Vec<Scalar>,
}

impl PolynomialS {
    // Initialize a polynomial with zero coefficients
    pub fn zero() -> Self {
        Self { coeffs: vec![Scalar::from(0u64)] }
    }

    // Add two polynomials (term-wise)
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result_coeffs = vec![Scalar::from(0u64); max_len];

        for i in 0..self.coeffs.len() {
            result_coeffs[i] += self.coeffs[i];
        }

        for i in 0..other.coeffs.len() {
            result_coeffs[i] += other.coeffs[i];
        }

        Self { coeffs: result_coeffs }
    }

    // Multiply polynomial by a scalar
    pub fn mul_scalar(&self, scalar: Scalar) -> Self {
        let result_coeffs: Vec<Scalar> = self.coeffs.iter().map(|c| *c * scalar).collect();
        Self { coeffs: result_coeffs }
    }

    // Add a single term
    pub fn add_term(&mut self, term: Scalar) {
        self.coeffs.push(term);
    }
}

pub fn lagrange_basis_polynomial(i: usize, n: usize) -> PolynomialS {
    let mut num = PolynomialS::zero();
    let mut denom = Scalar::from(1u64);

    for j in 0..n {
        if i != j {
            let j_scalar = Scalar::from(j as u64);
            let i_scalar = Scalar::from(i as u64);
            num = num.add(&PolynomialS { coeffs: vec![j_scalar, -Scalar::from(1u64)] });
            denom *= i_scalar - j_scalar;
        }
    }

    num.mul_scalar(denom.invert())
}

pub fn pad_to_next_power_of_2(mut vec: Vec<BaseElement>) -> Vec<BaseElement> {
    let mut size = vec.len();
    if size.is_power_of_two() {
        return vec;
    }

    size = size.next_power_of_two();
    vec.resize(size, BaseElement::ZERO);
    vec
}

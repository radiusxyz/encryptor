use std::fmt;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;

pub struct BlsScalarInfo {
  pub bls_scalar: BlsScalar,
  byte_length: usize,
}

impl BlsScalarInfo {
  pub const fn new(bls_scalar: BlsScalar, byte_length: usize) -> Self {
    Self { bls_scalar, byte_length }
  }

  pub fn to_bytes(&self) -> [u8; BlsScalar::SIZE] {
    self.bls_scalar.to_bytes()
  }
}

impl fmt::Debug for BlsScalarInfo {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{{blsScalar: {:?}, byteLength: {}}}", self.bls_scalar, self.byte_length)
  }
}

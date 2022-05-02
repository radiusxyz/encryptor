use crate::BlsScalarInfo;
use core::ops::Mul;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_hades::{ScalarStrategy, Strategy};
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
use std::{u64, usize};

const MESSAGE_CAPACITY: usize = 17;
const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;
const CIPHER_BYTES_SIZE: usize = CIPHER_SIZE * BlsScalar::SIZE;

/// Encapsulates an encrypted data
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Default)]
pub struct PoseidonEncryption {}

impl PoseidonEncryption {
  pub const fn new() -> Self {
    Self {}
  }

  pub const fn capacity() -> usize {
    MESSAGE_CAPACITY
  }

  pub const fn cipher_size() -> usize {
    CIPHER_SIZE
  }

  fn initial_state(secret: &JubJubAffine, nonce: BlsScalar) -> [BlsScalar; dusk_hades::WIDTH] {
    [
      // Domain - Maximum plaintext length of the elements of Fq, as defined in the paper
      BlsScalar::from_raw([0x100000000u64, 0, 0, 0]),
      // The size of the message is constant because any absent input is replaced by zero
      BlsScalar::from_raw([MESSAGE_CAPACITY as u64, 0, 0, 0]),
      secret.get_x(),
      secret.get_y(),
      nonce,
    ]
  }

  fn to_bytes(cipher_text: [BlsScalar; CIPHER_SIZE]) -> [u8; CIPHER_BYTES_SIZE] {
    let mut bytes = [0u8; CIPHER_BYTES_SIZE];

    cipher_text.iter().enumerate().for_each(|(i, c)| {
      let n = i * BlsScalar::SIZE;
      bytes[n..n + BlsScalar::SIZE].copy_from_slice(&c.to_bytes());
    });

    bytes
  }

  pub fn from_bytes(bytes: &[u8; CIPHER_BYTES_SIZE]) -> Result<[BlsScalar; CIPHER_SIZE], BytesError> {
    let mut cipher: [BlsScalar; CIPHER_SIZE] = [BlsScalar::zero(); CIPHER_SIZE];

    for (i, scalar) in cipher.iter_mut().enumerate() {
      let idx = i * BlsScalar::SIZE;
      let len = idx + BlsScalar::SIZE;
      *scalar = BlsScalar::from_slice(&bytes[idx..len])?;
    }

    Ok(cipher)
  }

  pub fn calculate_secret_key(y_bytes: &[u8]) -> JubJubAffine {
    let mut hasher = Keccak256::new();
    hasher.update(y_bytes);

    let result = hasher.finalize();
    let y_hash = format!("{:x}", result);
    let secret = y_hash.as_bytes().try_into().unwrap();
    let secret = JubJubScalar::from_bytes_wide(&secret);

    GENERATOR.to_niels().mul(&secret).into()
  }

  pub fn get_message_bls_scalar_vector(&self, message_bytes: &[u8]) -> [BlsScalar; PoseidonEncryption::capacity()] {
    let mut message_vecs: Vec<Vec<u8>> = message_bytes.to_vec().chunks(32).map(|s| s.into()).collect();
    let mut bls_scalars = Vec::new();

    for (_, message_vec) in message_vecs.iter_mut().enumerate() {
      let byte_length = message_vec.capacity();
      message_vec.resize(32, 0);
      
      let temp = &*message_vec;
      let message: [u8; 32] = temp.as_slice().try_into().unwrap();

      bls_scalars.push(BlsScalarInfo::new(BlsScalar::from_bytes(&message).unwrap(), byte_length));
    }

    let mut messages = [BlsScalar::zero(); PoseidonEncryption::capacity()];
    let mut index = 0;

    for (_, bls_scalar_info) in bls_scalars.iter().enumerate() {
      messages[index] = bls_scalar_info.bls_scalar;
      index += 1;
    }

    messages
  }

  pub fn encrypt(&self, message: String, secret: JubJubAffine) -> (Vec<String>, BlsScalar, [BlsScalar; PoseidonEncryption::capacity()], [BlsScalar; CIPHER_SIZE]) {
    let message_bls_scalar_vector = self.get_message_bls_scalar_vector(message.as_bytes());
    let (cipher_scalar, nonce) = self.encrypt_scalar(&message_bls_scalar_vector, &secret);
    let mut cipher_text_hexes = Vec::new();
    let cipher_text_bytes = PoseidonEncryption::to_bytes(cipher_scalar);

    cipher_text_hexes.push(hex::encode(cipher_text_bytes));
    (cipher_text_hexes, nonce, message_bls_scalar_vector, cipher_scalar)
  }

  pub fn encrypt_scalar(&self, message: &[BlsScalar], secret: &JubJubAffine) -> ([BlsScalar; CIPHER_SIZE], BlsScalar) {
    let zero = BlsScalar::zero();
    let nonce = BlsScalar::random(&mut OsRng);

    let mut strategy = ScalarStrategy::new();
    let mut cipher_scalar = [zero; CIPHER_SIZE];

    let count = (MESSAGE_CAPACITY + 3) / 4;

    let mut state = PoseidonEncryption::initial_state(&secret, nonce);

    (0..count).for_each(|i| {
      strategy.perm(&mut state);

      (0..4).for_each(|j| {
        if 4 * i + j < MESSAGE_CAPACITY {
          state[j + 1] += if 4 * i + j < message.len() { message[4 * i + j] } else { BlsScalar::zero() };
          cipher_scalar[4 * i + j] = state[j + 1];
        }
      });
    });

    strategy.perm(&mut state);
    cipher_scalar[MESSAGE_CAPACITY] = state[1];

    (cipher_scalar, nonce)
  }

  pub fn decrypt(&self, cipher_text_hexes: Vec<String>, secret: &JubJubAffine, nonce: String) -> Vec<u8> {
    let nonce: [u8; 32] = hex::decode(nonce).unwrap().try_into().unwrap();
    let nonce = BlsScalar::from_bytes(&nonce).unwrap();

    let mut result = Vec::new();
    for (_, cipher_text_hex) in cipher_text_hexes.iter().enumerate() {
      let chipher_text_hex_bytes = hex::decode(cipher_text_hex).unwrap().try_into().unwrap();
      let cipher_text = PoseidonEncryption::from_bytes(&chipher_text_hex_bytes).unwrap();

      let zero = BlsScalar::zero();
      let mut strategy = ScalarStrategy::new();
      let mut message = [zero; MESSAGE_CAPACITY];
      let mut state = PoseidonEncryption::initial_state(secret, nonce);

      let count = (MESSAGE_CAPACITY + 3) / 4;

      (0..count).for_each(|i| {
        strategy.perm(&mut state);

        (0..4).for_each(|j| {
          if 4 * i + j < MESSAGE_CAPACITY {
            message[4 * i + j] = cipher_text[4 * i + j] - state[j + 1];
            state[j + 1] = cipher_text[4 * i + j];
          }
        });
      });

      strategy.perm(&mut state);

      if cipher_text[MESSAGE_CAPACITY] != state[1] {
        return PoseidonEncryption::convert_bls_scalar_to_message(Vec::new());
      }

      result.extend_from_slice(&message);
    }

    PoseidonEncryption::convert_bls_scalar_to_message(result)
  }

  fn convert_bls_scalar_to_message(bls_scalars: Vec<BlsScalar>) -> Vec<u8> {
    let mut message = Vec::new();

    for (_, bls_scalar) in bls_scalars.iter().enumerate() {
      message.extend_from_slice(&bls_scalar.to_bytes());
    }

    message.try_into().unwrap()
  }
}

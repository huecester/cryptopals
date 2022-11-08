use crate::{
	types::Data,
	util::random_key,
};
use super::BlackBox;

pub struct Aes128EcbChosenPrefix([u8; 16]);

impl Aes128EcbChosenPrefix {
	pub const HIDDEN_STRING: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	pub fn new() -> Self {
		Self(random_key(&mut rand::thread_rng()))
	}
}

impl BlackBox for Aes128EcbChosenPrefix {
	fn encrypt(&self, data: impl Into<Data>) -> Data {
		let data: Data = data.into() + Data::from_b64(Self::HIDDEN_STRING).unwrap();
		data.pkcs7_pad(16).aes_128_ecb_encrypt(self.0)
	}
}

impl Default for Aes128EcbChosenPrefix {
	fn default() -> Self {
		Self::new()
	}
}
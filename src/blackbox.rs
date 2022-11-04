use crate::{
	Data,
	functions::random_key,
};

pub struct Aes128EcbBlackBox([u8; 16]);

impl Aes128EcbBlackBox {
	pub const HIDDEN_STRING: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	pub fn new() -> Self {
		Self(random_key(&mut rand::thread_rng()))
	}

	pub fn encrypt(&self, input: impl Into<Data>) -> Data {
		let input: Data = input.into() + Data::from_b64(Self::HIDDEN_STRING);
		input.pkcs7_pad(16).aes_128_ecb_encrypt(self.0)
	}
}

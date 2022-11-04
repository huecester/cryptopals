use std::{collections::HashMap, ops::Index};
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

pub struct UrlParams(HashMap<String, String>);

impl UrlParams {
	pub fn data(&self) -> &HashMap<String, String> {
		&self.0
	}
}

impl<T> From<T> for UrlParams where T: ToString {
	fn from(data: T) -> Self {
		let mut map = HashMap::new();
		data.to_string()
			.split('&')
			.map(|v| {
				let i = v.match_indices('=').next().expect("Malformed input, expected `=`.").0;
				(&v[..i], &v[i + 1..])
			})
			.for_each(|(k, v)| { map.insert(k.to_string(), v.to_string()); });

		Self(map)
	}
}
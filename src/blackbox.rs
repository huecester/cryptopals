use std::collections::HashMap;
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

#[derive(Clone, Debug, PartialEq)]
pub struct UrlParams(HashMap<String, String>, [u8; 16]);

impl UrlParams {
	pub fn profile_for(email: &str) -> Self {
		let email = email.replace('=', "").replace('&', "");
		let uid: usize = rand::random();
		Self::from(format!("email={email}&uid={uid}&role=user"))
	}

	pub fn encrypt(&self) -> Data {
		let params = self.0.iter()
			.map(|(k, v)| format!("{k}={v}"))
			.collect::<Vec<String>>()
			.join("&");
		Data::from(params).pkcs7_pad(16).aes_128_ecb_encrypt(self.1)
	}

	pub fn decrypt(&mut self, data: impl Into<Data>) -> &Self {
		let new_data = Self::from(data.into()
			.aes_128_ecb_decrypt(self.1)
			.pkcs7_unpad()
			.as_str()
			.unwrap());
		self.0 = new_data.0;
		self
	}

	pub fn get(&self, key: &str) -> &str {
		self.0.get(key).unwrap()
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

		Self(map, rand::random())
	}
}
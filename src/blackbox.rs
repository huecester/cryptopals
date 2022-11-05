use std::collections::HashMap;
use crate::{
	Data,
	functions::random_key,
};


pub trait BlackBox {
	fn encrypt(&self, data: impl Into<Data>) -> Data;

	fn aes_pkcs7_get_hidden_string_length(&self) -> usize {
		let ciphertext_with_padding_length = self.encrypt("").len();
		let mut padding_length = 0;
		while self.encrypt("A".repeat(padding_length)).len() == ciphertext_with_padding_length {
			padding_length += 1;
		}
		ciphertext_with_padding_length - padding_length
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParams([u8; 16]);

impl UrlParams {
	const UID: usize = 10;

	pub fn new() -> Self {
		Self(random_key(&mut rand::thread_rng()))
	}

	pub fn profile_for(&self, email: &str) -> Data {
		let email = email.replace(['=', '&'], "");
		let params = format!("email={email}&uid={}&role=user", Self::UID);
		self.encrypt(params)
	}

	pub fn decrypt_profile(&self, profile: impl Into<Data>) -> HashMap<String, String> {
		Self::parse(&self.decrypt(profile))
	}

	#[cfg(test)] fn profile_for_unencrypted(email: &str) -> HashMap<String, String> {
		let email = email.replace('=', "").replace('&', "");
		Self::parse(&format!("email={email}&uid={}&role=user", Self::UID))
	}

	fn parse<T>(data: &T) -> HashMap<String, String> where T: ToString + ?Sized{
		data.to_string()
			.split('&')
			.map(|v| {
				v.match_indices('=').next().map(|i| {
					let i = i.0;
					(v[..i].to_string(), v[i + 1..].to_string())
				})
			})
			.filter(Option::is_some)
			.flatten()
			.collect()
	}

	#[cfg(test)] fn encode(data: HashMap<String, String>) -> Data {
		data.iter()
			.map(|(k, v)| format!("{k}={v}"))
			.collect::<Vec<String>>()
			.join("&")
			.into()
	}

	fn decrypt(&self, data: impl Into<Data>) -> Data {
		data.into()
			.aes_128_ecb_decrypt(self.0)
			.pkcs7_unpad()
	}
}

impl BlackBox for UrlParams {
	fn encrypt(&self, data: impl Into<Data>) -> Data {
		data.into()
			.pkcs7_pad(16)
			.aes_128_ecb_encrypt(self.0)
	}

	fn aes_pkcs7_get_hidden_string_length(&self) -> usize {
		let ciphertext_with_padding_length = self.profile_for("").len();
		let mut padding_length = 0;
		while self.profile_for(&"A".repeat(padding_length)).len() == ciphertext_with_padding_length {
			padding_length += 1;
		}
		ciphertext_with_padding_length - padding_length
	}
}

impl Default for UrlParams {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)] mod url_params_tests {
	use super::*;

	#[test]
	fn params_can_be_parsed_and_encoded() {
		let data = UrlParams::parse("foo=bar&baz=qux&zap=zazzle");
		assert_eq!("bar", data.get("foo").unwrap());
		assert_eq!("qux", data.get("baz").unwrap());
		assert_eq!("zazzle", data.get("zap").unwrap());

		let encoded = UrlParams::encode(data).to_string();
		assert!(encoded.contains("foo=bar"));
		assert!(encoded.contains("baz=qux"));
		assert!(encoded.contains("zap=zazzle"));
	}

	#[test]
	fn encryption_and_decryption_work() {
		let profile = UrlParams::profile_for_unencrypted("foo@bar.com");
		assert_eq!("foo@bar.com", profile.get("email").unwrap());
		assert_eq!("user", profile.get("role").unwrap());

		let profile = UrlParams::encode(profile);
		let params = UrlParams::new();
		assert_eq!(&profile, &params.decrypt(params.encrypt(profile.bytes.clone())))
	}

	#[test]
	fn plaintext_injection_is_not_possible() {
		let profile = UrlParams::profile_for_unencrypted("foo@bar.com&role=admin");
		assert_eq!("user", profile.get("role").unwrap());
	}

}

#[cfg(test)] pub use challenges::*;
#[cfg(test)] mod challenges {
	use super::*;

	pub struct Aes128EcbBlackBox([u8; 16]);

	impl Aes128EcbBlackBox {
		pub const HIDDEN_STRING: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

		pub fn new() -> Self {
			Self(random_key(&mut rand::thread_rng()))
		}
	}

	impl BlackBox for Aes128EcbBlackBox {
		fn encrypt(&self, data: impl Into<Data>) -> Data {
			let data: Data = data.into() + Data::from_b64(Self::HIDDEN_STRING);
			data.pkcs7_pad(16).aes_128_ecb_encrypt(self.0)
		}
	}
}
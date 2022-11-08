use std::collections::HashMap;
use super::{AesPkcs7, BlackBox};
use crate::{
	types::Data,
	util::random_key,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParams([u8; 16]);

impl UrlParams {
	const UID: usize = 10;

	pub fn new() -> Self {
		Self(random_key(&mut rand::thread_rng()))
	}

	pub fn decrypt(&self, data: impl Into<Data>) -> HashMap<String, String> {
		Self::parse(&data.into()
			.aes_128_ecb_decrypt(self.0)
			.pkcs7_unpad()
		)
	}

	fn email_string(email: &str) -> String {
		let email = email.replace(['=', '&'], "");
		format!("email={email}&uid={}&role=user", Self::UID)
	}

	#[cfg(test)] fn profile_for_unencrypted(email: &str) -> HashMap<String, String> {
		Self::parse(&Self::email_string(email))
	}

	fn parse<T>(data: &T) -> HashMap<String, String> where T: ToString + ?Sized {
		data.to_string()
			.split('&')
			.map(|v| v.split_once('=').map(|s| (s.0.to_owned(), s.1.to_owned())))
			.filter(Option::is_some)
			.flatten()
			.collect()
	}
}

impl AesPkcs7 for UrlParams {}

impl BlackBox for UrlParams {
	fn encrypt(&self, data: impl Into<Data>) -> Data {
		Data::from(Self::email_string(&data.into().to_string()))
			.pkcs7_pad(16)
			.aes_128_ecb_encrypt(self.0)
	}
}

impl Default for UrlParams {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)] mod tests {
	use super::*;
	use pretty_assertions::assert_eq;

	#[test]
	fn parsing_works() {
		let data = UrlParams::parse("foo=bar&baz=qux&zap=zazzle");
		assert_eq!("bar", data.get("foo").unwrap());
		assert_eq!("qux", data.get("baz").unwrap());
		assert_eq!("zazzle", data.get("zap").unwrap());
	}

	#[test]
	fn encryption_and_decryption_work() {
		let profile = UrlParams::profile_for_unencrypted("foo@bar.com");
		assert_eq!("foo@bar.com", profile.get("email").unwrap());
		assert_eq!("user", profile.get("role").unwrap());
		assert_eq!("10", profile.get("uid").unwrap());

		let params = UrlParams::new();
		assert_eq!(profile, params.decrypt(params.encrypt("foo@bar.com")))
	}

	#[test]
	fn plaintext_injection_is_not_possible() {
		let profile = UrlParams::profile_for_unencrypted("foo@bar.com&role=admin");
		assert_eq!("user", profile.get("role").unwrap());
	}

}
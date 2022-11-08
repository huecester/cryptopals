mod aes_128_ecb_chosen_prefix;
mod url_params;

pub use aes_128_ecb_chosen_prefix::Aes128EcbChosenPrefix;
pub use url_params::UrlParams;

use crate::types::Data;

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

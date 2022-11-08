use super::BlackBox;

pub trait AesPkcs7: BlackBox {
	fn aes_pkcs7_get_hidden_string_length(&self) -> usize {
		let ciphertext_with_padding_length = self.encrypt("").len();
		let mut padding_length = 0;
		while self.encrypt("A".repeat(padding_length)).len() == ciphertext_with_padding_length {
			padding_length += 1;
		}
		ciphertext_with_padding_length - padding_length
	}
}
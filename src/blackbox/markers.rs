use super::BlackBox;

pub trait AesPkcs7: BlackBox {
	fn hidden_prefix_string_properties(&self) -> (usize, usize) {
		let hidden_string_length = self.encrypt("").len();
		let mut padding_to_next_block_length = 0;
		while self.encrypt("A".repeat(padding_to_next_block_length)).len() == hidden_string_length {
			padding_to_next_block_length += 1;
		}

		// (hidden string length, padding to next block length)
		(hidden_string_length - padding_to_next_block_length, padding_to_next_block_length)
	}

	fn hidden_string_length(&self) -> usize {
		let (hidden_string_length, _) = self.hidden_prefix_string_properties();
		hidden_string_length
	}

	fn block_size(&self) -> usize {
		let (_, padding_to_next_block_length) = self.hidden_prefix_string_properties();
		let base_output = self.encrypt("A".repeat(padding_to_next_block_length));
		let mut i = 1;
		loop {
			let output = self.encrypt("A".repeat(i + padding_to_next_block_length));
			if output.len() != base_output.len() {
				return i
			}
			i += 1;
		}
	}
}
mod tables;
mod types;

#[cfg(test)] mod set_1;

use std::ops::BitXor;
use tables::FREQUENCIES;
use types::Result;

const NON_GRAPHIC_PENALTY: i64 = -100000;

pub type Guess = (Data, i64);

#[derive(Debug)]
pub struct Data {
	bytes: Vec<u8>,
}

impl Data {
	pub fn guess_single_byte_xor(&self) -> Vec<Guess> {
		let mut guesses: Vec<Guess> = (u8::MIN..=u8::MAX)
			.map(|byte|  {
				let byte = Data::from(vec![byte]);
				let guess = self ^ &byte;
				let score = guess.score();
				(guess, score)
			})
			.collect();
		guesses.sort_by_key(|k| -k.1);
		guesses
	}

	fn score(&self) -> i64 {
		self.bytes
			.iter()
			.fold(0, |acc, byte|
				acc + byte.to_owned()
					.try_into()
					.ok()
					.and_then(|c|
						Some(FREQUENCIES.get(&c)
							.copied()
							.unwrap_or_else(|| {
								if c.is_ascii_graphic() {
									0
								} else {
									NON_GRAPHIC_PENALTY
								}
							}))
					)
					.unwrap_or(0)
				)
	}

	pub fn from_hex(data: &str) -> Result<Self> {
		Ok(
			Self {
				bytes: hex::decode(data)?,
			}
		)
	}

	pub fn from_b64(data: &str) -> Result<Self> {
		Ok(
			Self {
				bytes: base64::decode(data)?,
			}
		)
	}

	pub fn as_hex(&self) -> String {
		hex::encode(&self.bytes)
	}

	pub fn as_b64(&self) -> String {
		base64::encode(&self.bytes)
	}

	pub fn as_str(&self) -> Option<String> {
		String::from_utf8(self.bytes.clone()).ok()
	}

	pub fn len(&self) -> usize {
		self.bytes.len()
	}
}

impl<T> From<T> for Data where T: Into<Vec<u8>> {
	fn from(data: T) -> Self {
		Self {
			bytes: data.into(),
		}
	}
}

impl BitXor for &Data {
	type Output = Data;

	fn bitxor(self, rhs: Self) -> Self::Output {
		if rhs.len() != 1 && self.len() != rhs.len() {
			panic!("Data must be equal length or RHS must be one byte to XOR.");
		}

		if rhs.len() == 1 {
			let byte = rhs.bytes[0];
			Self::Output {
				bytes: self.bytes.iter().map(|lhs| lhs ^ byte).collect(),
			}
		} else {
			Self::Output {
				bytes: self.bytes.iter().zip(rhs.bytes.iter()).map(|(lhs, rhs)| lhs ^ rhs).collect(),
			}
		}
	}
}

impl BitXor for Data {
	type Output = Data;

	fn bitxor(self, rhs: Self) -> Self::Output {
		&self ^ &rhs
	}
}
mod tables;
mod types;

#[cfg(test)] mod set_1;

use std::ops::BitXor;
use tables::FREQUENCIES;
use types::Result;

const NON_GRAPHIC_PENALTY: i32 = -100000;

pub type Guess = (Data, i32);

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

	fn score(&self) -> i32 {
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
		let bytes = self.bytes
			.iter()
			.zip(rhs.bytes.repeat(self.len() / rhs.len() + 1).iter())
			.map(|(lhs, rhs)| lhs ^ rhs)
			.collect();

		Self::Output {
			bytes,
		}
	}
}

impl BitXor<&str> for &Data {
	type Output = Data;

	fn bitxor(self, rhs: &str) -> Self::Output {
		self ^ &Data::from(rhs)
	}
}

impl BitXor for Data {
	type Output = Data;

	fn bitxor(self, rhs: Self) -> Self::Output {
		&self ^ &rhs
	}
}

impl BitXor<&str> for Data {
	type Output = Data;

	fn bitxor(self, rhs: &str) -> Self::Output {
		&self ^ rhs
	}
}
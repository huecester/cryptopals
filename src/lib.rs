mod tables;
mod types;

#[cfg(test)] mod set_1;
#[cfg(test)] mod set_2;

use std::ops::BitXor;

use tables::FREQUENCIES;
use types::Result;

use aes::{
	Aes128,
	cipher::{
		BlockDecrypt,
		KeyInit,
		generic_array::GenericArray,
	},
};

const NON_GRAPHIC_PENALTY: i32 = -100000;

pub type Guess = (Data, i32);

#[derive(Debug)]
pub struct Data {
	bytes: Vec<u8>,
}

impl Data {
	pub fn aes_128_ecb_decrypt(&self, key: impl Into<Data>) -> Data {
		let key = GenericArray::clone_from_slice(&key.into().bytes[0..16]);
		let cipher = Aes128::new(&key);

		let mut blocks: Vec<_> = (0..self.bytes.len()).step_by(16)
			.map(|i| GenericArray::clone_from_slice(&self.bytes[i..i+16]))
			.collect();
		cipher.decrypt_blocks(&mut blocks);
		Data::from(blocks.iter().flatten().copied().collect::<Vec<u8>>())
	}

	fn pkcs7_pad(&mut self, n: u8) -> &Data {
		let padding = n - (self.len() % (n as usize)) as u8;
		self.bytes.extend(std::iter::repeat(padding).take(padding as usize));
		self
	}

	pub fn guess_repeating_key_xor(&self) -> Data {
		let keysize = (2..=40.max(self.len() / 2))
			.fold((0, 0), |acc, keysize| {
				let (dist, count) = self.bytes
					.chunks_exact(keysize)
					.zip(self.bytes.chunks_exact(keysize).skip(1))
					.fold((0, 0), |acc, (lhs, rhs)| {
						(acc.0 + Data::from(lhs).hamming_distance(rhs), acc.1 + 1)
					});

				if acc.0 == 0 || dist / (keysize * count) < acc.1 {
					(keysize, dist / (keysize * count))
				} else {
					acc
				}
			}).0;

		let blocks: Vec<Data> = (0..keysize).map(|i| {
			let block: Vec<u8> = self.bytes
				.iter()
				.copied()
				.skip(i)
				.step_by(keysize)
				.collect();

			Data::from(block).guess_single_byte_xor().0
		}).collect();

		let res: Vec<u8> = (0..blocks[0].len()).fold(vec![], |mut acc, i| {
			for block in &blocks {
				if let Some(byte) = block.bytes.get(i) {
					acc.push(byte.to_owned());
				}
			}
			acc
		});

		Data::from(res)
	}

	fn hamming_distance(&self, rhs: impl Into<Data>) -> usize {
		self.bytes
			.iter()
			.zip(rhs.into().bytes.iter())
			.fold(0, |acc, (lhs, rhs)| acc + (lhs ^ rhs).count_ones() as usize)
	}

	pub fn guess_single_byte_xor(&self) -> Guess {
		let guess: (Option<Data>, i32) = (u8::MIN..=u8::MAX)
			.fold((None, 0), |acc, byte| {
				let byte = Data::from(vec![byte]);
				let guess = self ^ &byte;
				let score = guess.score();
				if acc.0.is_none() || score > acc.1 {
					(Some(guess), score)
				} else {
					acc
				}
			});

		(guess.0.unwrap(), guess.1)
	}

	fn score(&self) -> i32 {
		self.bytes
			.iter()
			.fold(0, |acc, byte|
				acc + byte.to_owned()
					.try_into()
					.ok()
					.map_or(0, |c|
						FREQUENCIES.get(&c)
							.copied()
							.unwrap_or_else(|| {
								if c.is_ascii_graphic() {
									0
								} else {
									NON_GRAPHIC_PENALTY
								}
							})
					)
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

	pub fn is_empty(&self) -> bool {
		self.bytes.is_empty()
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
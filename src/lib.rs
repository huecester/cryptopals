mod tables;
mod functions;
pub mod blackbox;

#[cfg(test)] mod set_1;
#[cfg(test)] mod set_2;

use std::{
	ops::{Add, BitXor},
	collections::HashMap,
};

use tables::FREQUENCIES;

use aes::{
	Aes128Dec,
	Aes128Enc,
	cipher::{
		BlockDecrypt,
		BlockEncrypt,
		KeyInit,
		generic_array::GenericArray,
	},
};

const NON_GRAPHIC_PENALTY: i32 = -100000;

pub type Guess = (Data, i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesMode {
	CBC,
	ECB,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
	bytes: Vec<u8>,
}

impl Data {
	pub fn aes_128_ecb_cbc_oracle(&self) -> AesMode {
		if self.aes_128_ecb_percent() > 0 {
			AesMode::ECB
		} else {
			AesMode::CBC
		}
	}

	pub fn aes_128_ecb_percent(&self) -> usize {
		let reps = self.bytes
			.chunks_exact(16)
			.fold(HashMap::<&[u8], usize>::new(), |mut map, block| {
				if let Some(val) = map.get(block) {
					map.insert(block, val + 1);
				} else {
					map.insert(block, 0);
				}
				map
			})
			.values()
			.sum::<usize>();
		(reps * 1000) / self.bytes.chunks_exact(16).count()
	}

	pub fn aes_128_cbc_encrypt(&self, key: impl Into<Vec<u8>>, iv: impl Into<Vec<u8>>) -> Self {
		let key = GenericArray::clone_from_slice(&key.into()[..16]);
		let cipher = Aes128Enc::new(&key);
		let iv = Data::from(&iv.into()[..16]);

		let bytes: Vec<u8> = self.bytes
			.chunks_exact(16)
			.fold((vec![], iv), |(mut blocks, xor), block| {
				let mut block = GenericArray::clone_from_slice(&(xor ^ block).bytes[..16]);
				cipher.encrypt_block(&mut block);
				let block = Self::from(block.to_vec());
				blocks.push(block.bytes.clone());
				(blocks, block)
			})
			.0
			.into_iter()
			.flatten()
			.collect();

		Self::from(bytes)
	}

	pub fn aes_128_cbc_decrypt(&self, key: impl Into<Vec<u8>>, iv: impl Into<Vec<u8>>) -> Self {
		let key = GenericArray::clone_from_slice(&key.into()[..16]);
		let cipher = Aes128Dec::new(&key);
		let iv = Self::from(&iv.into()[..16]);
		let xor_data = vec![
			vec![iv],
			self.bytes.chunks_exact(16).map(Self::from).collect(),
		];

		let bytes: Vec<u8> = self.bytes
			.chunks_exact(16)
			.zip(xor_data.iter().flatten())
			.map(|(block, xor)| {
				let mut block = GenericArray::clone_from_slice(&block[..16]);
				cipher.decrypt_block(&mut block);
				xor ^ block.to_vec()
			})
			.flat_map(|data| data.bytes)
			.collect();

		Self::from(bytes)
	}

	pub fn aes_128_ecb_encrypt(&self, key: impl Into<Vec<u8>>) -> Self {
		let key = GenericArray::clone_from_slice(&key.into()[..16]);
		let cipher = Aes128Enc::new(&key);

		let mut blocks: Vec<_> = self.bytes.chunks_exact(16)
			.map(GenericArray::clone_from_slice)
			.collect();
		cipher.encrypt_blocks(&mut blocks);
		Self::from(blocks.iter().flatten().copied().collect::<Vec<u8>>())
	}

	pub fn aes_128_ecb_decrypt(&self, key: impl Into<Vec<u8>>) -> Self {
		let key = GenericArray::clone_from_slice(&key.into()[..16]);
		let cipher = Aes128Dec::new(&key);

		let mut blocks: Vec<_> = self.bytes.chunks_exact(16)
			.map(GenericArray::clone_from_slice)
			.collect();
		cipher.decrypt_blocks(&mut blocks);
		Self::from(blocks.iter().flatten().copied().collect::<Vec<u8>>())
	}

	fn pkcs7_pad(&self, n: u8) -> Self {
		let padding = n - (self.len() % (n as usize)) as u8;
		let mut bytes = self.bytes.clone();
		bytes.extend(std::iter::repeat(padding).take(padding as usize));

		Self {
			bytes,
		}
	}

	fn pkcs7_unpad(&self) -> Self {
		let padding = *self.bytes.last().unwrap();
		assert!(
			self.bytes.iter().rev().take(padding as usize).all(|b| b == &padding),
			"Trying to undo PKCS#7 padding on non-PKCS#7 padded data."
		);
		Self::from(&self.bytes[..self.bytes.len() - padding as usize])
	}

	pub fn guess_repeating_key_xor(&self) -> Self {
		let keysize = (2..=40.max(self.len() / 2))
			.fold((0, 0), |acc, keysize| {
				let (dist, count) = self.bytes
					.chunks_exact(keysize)
					.zip(self.bytes.chunks_exact(keysize).skip(1))
					.fold((0, 0), |acc, (lhs, rhs)| {
						(acc.0 + Self::from(lhs).hamming_distance(rhs), acc.1 + 1)
					});

				if acc.0 == 0 || dist / (keysize * count) < acc.1 {
					(keysize, dist / (keysize * count))
				} else {
					acc
				}
			}).0;

		let blocks: Vec<Self> = (0..keysize).map(|i| {
			let block: Vec<u8> = self.bytes
				.iter()
				.copied()
				.skip(i)
				.step_by(keysize)
				.collect();

			Self::from(block).guess_single_byte_xor().0
		}).collect();

		let res: Vec<u8> = (0..blocks[0].len()).fold(vec![], |mut acc, i| {
			for block in &blocks {
				if let Some(byte) = block.bytes.get(i) {
					acc.push(byte.to_owned());
				}
			}
			acc
		});

		Self::from(res)
	}

	fn hamming_distance(&self, rhs: impl Into<Vec<u8>>) -> usize {
		self.bytes
			.iter()
			.zip(rhs.into().iter())
			.fold(0, |acc, (lhs, rhs)| acc + (lhs ^ rhs).count_ones() as usize)
	}

	pub fn guess_single_byte_xor(&self) -> Guess {
		let guess: (Option<Self>, i32) = (u8::MIN..=u8::MAX)
			.fold((None, 0), |(acc_guess, acc_score), byte| {
				let byte = Self::from(vec![byte]);
				let guess = self ^ byte;
				let score = guess.score();
				if acc_guess.is_none() || score > acc_score {
					(Some(guess), score)
				} else {
					(acc_guess, acc_score)
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

	pub fn from_hex(data: &str) -> Self {
		Self {
			bytes: hex::decode(data).unwrap(),
		}
	}

	pub fn from_b64(data: &str) -> Self {
		Self {
			bytes: base64::decode(data).unwrap(),
		}
	}

	pub fn as_hex(&self) -> String {
		hex::encode(&self.bytes)
	}

	pub fn as_b64(&self) -> String {
		base64::encode(&self.bytes)
	}

	pub fn len(&self) -> usize {
		self.bytes.len()
	}

	pub fn is_empty(&self) -> bool {
		self.bytes.is_empty()
	}
}

impl<T> Add<T> for &Data where T: Into<Data> {
	type Output = Data;

	fn add(self, rhs: T) -> Self::Output {
		let mut bytes = self.bytes.clone();
		let mut other = rhs.into().bytes;
		bytes.append(&mut other);

		Self::Output {
			bytes,
		}
	}
}

impl<T> Add<T> for Data where T: Into<Self> {
	type Output = Self;

	fn add(self, rhs: T) -> Self::Output {
		&self + rhs
	}
}

impl<T> BitXor<T> for &Data where T: Into<Data> {
	type Output = Data;

	fn bitxor(self, rhs: T) -> Self::Output {
		let rhs = rhs.into();
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

impl<T> BitXor<T> for Data where T: Into<Data> {
	type Output = Self;

	fn bitxor(self, rhs: T) -> Self::Output {
		&self ^ rhs
	}
}

impl<T> From<T> for Data where T: Into<Vec<u8>> {
	fn from(data: T) -> Self {
		Self {
			bytes: data.into(),
		}
	}
}

impl ToString for Data {
	fn to_string(&self) -> String {
		String::from_utf8(self.bytes.clone()).unwrap()
	}
}
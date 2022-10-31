mod types;
#[cfg(test)] mod set_1;

use std::ops::BitXor;

use types::Result;

pub struct Data {
	bytes: Vec<u8>,
}

impl Data {
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

	pub fn len(&self) -> usize {
		self.bytes.len()
	}
}

impl BitXor for Data {
	type Output = Self;

	fn bitxor(self, rhs: Self) -> Self::Output {
		if self.len() != rhs.len() {
			panic!("Data must be equal length to XOR.");
		}

		Self {
			bytes: self.bytes.iter().zip(rhs.bytes.iter()).map(|(lhs, rhs)| lhs ^ rhs).collect(),
		}
	}
}
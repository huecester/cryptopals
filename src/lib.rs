mod types;
#[cfg(test)] mod set_1;

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
}
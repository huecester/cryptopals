#[cfg(test)] pub(crate) mod aes_128_ecb_chosen_prefix;
pub mod markers;
pub mod url_params;

#[cfg(test)] pub(crate) use aes_128_ecb_chosen_prefix::Aes128EcbChosenPrefix;
pub use url_params::UrlParams;
pub use markers::AesPkcs7;

use crate::types::Data;

pub trait BlackBox {
	fn encrypt(&self, data: impl Into<Data>) -> Data;
}

pub mod data;
pub use data::Data;

pub type Guess = (Data, i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesMode {
	CBC,
	ECB,
}

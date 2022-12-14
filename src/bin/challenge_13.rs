use std::io::{self, prelude::*};
use anyhow::Result;
use cryptopals::{
	blackbox::{BlackBox, UrlParams},
	types::Data,
};

fn main() -> Result<()> {
	let params = UrlParams::new();
	let stdin = io::stdin();
	let mut input = String::new();

	loop {
		print!("Enter email or encoded profile: ");
		io::stdout().flush()?;

		input.clear();
		stdin.read_line(&mut input)?;
		let input = input.trim();

		if !input.is_empty() && hex::decode(input).is_ok() {
			println!("Profile: {:#?}", params.decrypt(Data::from_hex(input)?));
		} else {
			let data = params.encrypt(input);
			println!("   Data: {}", data.as_hex());
		}
	}
}
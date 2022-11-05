use std::io::{self, prelude::*};
use cryptopals::{
	Data,
	blackbox::UrlParams,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
			println!("Profile: {:#?}", params.decrypt_profile(Data::from_hex(input)));
		} else {
			let data = params.profile_for(input);
			println!("   Data: {}", data.as_hex());
		}
	}
}
use std::fs::read_to_string;
use crate::{Data, Guess};

#[test]
fn challenge_1() {
	let data = Data::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
	assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", data.as_b64());
}

#[test]
fn challenge_2() {
	let data1 = Data::from_hex("1c0111001f010100061a024b53535009181c").unwrap();
	let data2 = Data::from_hex("686974207468652062756c6c277320657965").unwrap();
	println!("{} {}", data1.len(), data2.len());
	assert_eq!("746865206b696420646f6e277420706c6179", (data1 ^ data2).as_hex());
}

#[test]
fn challenge_3() {
	let data = Data::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
	let guess = data.guess_single_byte_xor();
	assert_eq!("Cooking MC's like a pound of bacon", guess[0].0.as_str().unwrap());
}

#[test]
fn challenge_4() {
	let lines = read_to_string("res/1-4.txt").unwrap();
	let mut guesses: Vec<Guess> = lines.split_ascii_whitespace()
		.flat_map(|line| {
			let data = Data::from_hex(line).unwrap();
			data.guess_single_byte_xor()
		})
		.collect();
	guesses.sort_by_key(|k| -k.1);
	assert_eq!("Now that the party is jumping\n", guesses[0].0.as_str().unwrap());
}
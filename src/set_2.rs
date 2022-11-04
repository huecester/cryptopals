use std::fs::read_to_string;
use rand::prelude::*;

use crate::{AesMode, Data};

fn random_key(rand: &mut ThreadRng) -> [u8; 16] {
	let mut key = [0u8; 16];
	rand.fill_bytes(&mut key);
	key
}

fn random_encrypt(plaintext: impl Into<Vec<u8>>, mode: Option<AesMode>) -> (Data, AesMode) {
	let mut rand = rand::thread_rng();

	let mut plaintext = plaintext.into();
	let prefix_count = rand.gen_range(5..=10);
	let suffix_count = rand.gen_range(5..=10);
	for i in 0..prefix_count {
		plaintext.insert(i, rand.gen());
	}
	for _ in 0..suffix_count {
		plaintext.push(rand.gen());
	}
	let plaintext = Data::from(plaintext).pkcs7_pad(16);

	let key = random_key(&mut rand);

	if let Some(mode) = mode {
		match mode {
			AesMode::ECB => (plaintext.aes_128_ecb_encrypt(key), AesMode::ECB),
			AesMode::CBC => {
				let mut iv = [0u8; 16];
				rand.fill_bytes(&mut iv);
				(plaintext.aes_128_cbc_encrypt(key, iv), AesMode::CBC)
			},
		}
	} else {
		if rand.gen_ratio(1, 2) {
			// ECB
			(plaintext.aes_128_ecb_encrypt(key), AesMode::ECB)
		} else {
			// CBC
			let mut iv = [0u8; 16];
			rand.fill_bytes(&mut iv);
			(plaintext.aes_128_cbc_encrypt(key, iv), AesMode::CBC)
		}
	}
}

struct Aes128EcbBlackBox([u8; 16]);

impl Aes128EcbBlackBox {
	const HIDDEN_STRING: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	fn new() -> Self {
		Self(random_key(&mut rand::thread_rng()))
	}

	fn encrypt(&self, input: impl Into<Data>) -> Data {
		let input: Data = input.into() + Data::from_b64(Self::HIDDEN_STRING);
		input.pkcs7_pad(16).aes_128_ecb_encrypt(self.0)
	}
}

#[test]
fn challenge_9() {
	assert_eq!(
		Data::from("YELLOW SUBMARINE").pkcs7_pad(20),
		Data::from("YELLOW SUBMARINE\x04\x04\x04\x04")
	);
}

#[test]
fn aes_128_ecb_encrypt_test() {
	let plaintext = Data::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}");
	let ciphertext = plaintext.aes_128_ecb_encrypt("YELLOW SUBMARINE");
	assert_eq!(Data::from_b64(&read_to_string("res/7.txt").unwrap().replace('\n', "")), ciphertext);
}

#[test]
fn challenge_10() {
	let ciphertext = Data::from_b64(&read_to_string("res/10.txt").unwrap().replace('\n', ""));
	let plaintext = ciphertext.aes_128_cbc_decrypt("YELLOW SUBMARINE", [0; 16]);
	println!("{:?}", plaintext.as_str());
	assert_eq!(
		Data::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}"),
		plaintext
	);
}

#[test]
fn aes_128_cbc_encrypt_test() {
	let plaintext = Data::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}");
	let ciphertext = plaintext.aes_128_cbc_encrypt("YELLOW SUBMARINE", [0; 16]);
	assert_eq!(Data::from_b64(&read_to_string("res/10.txt").unwrap().replace('\n', "")), ciphertext);
}

#[test]
#[ignore = "slow"]
fn challenge_11() {
	{
		let plaintext = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}";
		for _ in 0..1000 {
			{
				let ciphertext = random_encrypt(plaintext, Some(AesMode::ECB)).0;
				assert_eq!(AesMode::ECB, ciphertext.aes_128_ecb_cbc_oracle());
			}
			{
				let ciphertext = random_encrypt(plaintext, Some(AesMode::CBC)).0;
				assert_eq!(AesMode::CBC, ciphertext.aes_128_ecb_cbc_oracle());
			}
			{
				let (ciphertext, mode) = random_encrypt(plaintext, None);
				assert_eq!(mode, ciphertext.aes_128_ecb_cbc_oracle());
			}
		}
	}
}

#[test]
fn challenge_12() {
	let black_box = Aes128EcbBlackBox::new();

	let block_size = {
		let mut i = 1;
		loop {
			let output = black_box.encrypt("A".repeat(i * 2));
			if output.bytes[..i] == output.bytes[i..i*2] { break; }
			i += 1;
		}
		i
	};

	assert_eq!(AesMode::ECB, black_box.encrypt("A".repeat(block_size * 4)).aes_128_ecb_cbc_oracle());

	let hidden_string_length = {
		let ciphertext_with_padding_length = black_box.encrypt("").len();
		let mut padding_length = 1;
		while black_box.encrypt("A".repeat(padding_length)).len() == ciphertext_with_padding_length {
			padding_length += 1;
		}
		ciphertext_with_padding_length - padding_length
	};
	let rounded_hidden_string_length = ((hidden_string_length / block_size) + 1) * block_size;

	let mut known_hidden_string = String::from("");
	'outer: for i in (0..=rounded_hidden_string_length - 1).rev() {
		let padding = "A".repeat(i);
		let key = &black_box.encrypt(&padding[..]).bytes[..rounded_hidden_string_length];

		for b in u8::MIN..=u8::MAX {
			let b = &(b as char).to_string();

			let test_string = format!("{}{}{}", &padding, &known_hidden_string, b);
			let test = &black_box.encrypt(test_string).bytes[..rounded_hidden_string_length];

			if test == key {
				known_hidden_string += b;
				if known_hidden_string.len() >= hidden_string_length {
					break 'outer;
				} else {
					continue 'outer;
				}
			}
		}
	}

	assert_eq!(Data::from_b64(Aes128EcbBlackBox::HIDDEN_STRING), Data::from(known_hidden_string));
}
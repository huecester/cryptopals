use std::{
	collections::HashSet,
	fs::read_to_string,
};
use crate::{
	types::{AesMode, Data},
	blackbox::{Aes128EcbChosenPrefix, AesPkcs7, BlackBox, UrlParams},
	util::random_encrypt,
};
use anyhow::{Result, anyhow};
use pretty_assertions::assert_eq;

#[test]
fn challenge_9() {
	assert_eq!(
		Data::from("YELLOW SUBMARINE").pkcs7_pad(20),
		Data::from("YELLOW SUBMARINE\x04\x04\x04\x04")
	);
}

#[test]
fn challenge_10() -> Result<()> {
	let ciphertext = Data::from_b64(&read_to_string("res/10.txt")?.replace('\n', ""))?;
	let plaintext = ciphertext.aes_128_cbc_decrypt("YELLOW SUBMARINE", [0; 16]);
	println!("{:?}", plaintext.to_string());
	assert_eq!(
		Data::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}"),
		plaintext
	);
	Ok(())
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
#[ignore = "slow"]
fn challenge_12() -> Result<()> {
	let black_box = Aes128EcbChosenPrefix::new();

	let block_size = black_box.block_size();

	assert_eq!(AesMode::ECB, black_box.encrypt("A".repeat(block_size * 4)).aes_128_ecb_cbc_oracle());

	let hidden_string_length = black_box.hidden_string_length();
	let rounded_hidden_string_length = ((hidden_string_length / block_size) + 1) * block_size;

	let mut known_hidden_string = String::from("");
	'outer: for i in (0..=rounded_hidden_string_length - 1).rev() {
		let padding = "A".repeat(i);
		let key_data = &black_box.encrypt(&padding[..]);
		let key = &key_data.bytes()[..rounded_hidden_string_length];

		for b in u8::MIN..=u8::MAX {
			let b = &(b as char).to_string();

			let test_string = format!("{}{}{}", &padding, &known_hidden_string, b);
			let test_data = &black_box.encrypt(test_string);
			let test = &test_data.bytes()[..rounded_hidden_string_length];

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

	assert_eq!(Data::from_b64(Aes128EcbChosenPrefix::HIDDEN_STRING)?, Data::from(known_hidden_string));
	Ok(())
}

#[test]
fn challenge_13() -> Result<()> {
	let black_box = UrlParams::new();
	let block_size = black_box.block_size();
	let hidden_string_length = black_box.hidden_string_length();
	let rounded_hidden_string_length = ((hidden_string_length / block_size) + 1) * block_size;
	let padding_length = rounded_hidden_string_length - hidden_string_length;

	let encrypted_without_user = {
		let padding = "A".repeat(padding_length + 4);
		let encrypted = black_box.encrypt(padding);
		encrypted.bytes()[..rounded_hidden_string_length].to_owned()
	};

	let encrypted_admin_block = {
		let (prefix_padding_to_next_block, prefix_length) = {
			let mut i = 0;
			loop {
				let mut set = HashSet::new();
				let output = black_box.encrypt("A".repeat(i + block_size * 2));
				let bytes = output.bytes();
				if !bytes.chunks_exact(block_size).all(|block| set.insert(block)) {
					set.clear();
					let dup_block_i = bytes.chunks_exact(block_size).position(|block| !set.insert(block)).unwrap();
					break (i, (dup_block_i * block_size) - block_size - i);
				}
				i += 1;
			}
		};

		let encrypted_with_admin = black_box.encrypt(
			format!(
				"{}{}",
				"A".repeat(prefix_padding_to_next_block),
				Data::from("admin").pkcs7_pad(block_size as u8).to_string(),
			)
		);
		let i = prefix_padding_to_next_block + prefix_length;
		&encrypted_with_admin.bytes()[i..i + block_size].to_owned()
	};

	let mut payload = vec![];
	payload.extend(encrypted_without_user);
	payload.extend(encrypted_admin_block);
	let profile = black_box.decrypt(payload);

	assert_eq!("admin", profile.get("role").ok_or(anyhow!("No role in profile."))?);
	Ok(())
}
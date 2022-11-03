use std::{
	collections::HashMap,
	fs::read_to_string,
};
use crate::Data;

fn detect_aes_128_ecb(data: &[Data]) -> &Data {
	data.into_iter()
		.fold((None, 0), |(acc_max, acc_reps), data| {
			let reps = data.bytes
			 	.chunks_exact(16)
				.fold(HashMap::new(), |mut map: HashMap<&[u8], i32>, block| {
					map.insert(block, map.get(block).copied().unwrap_or(-1) + 1);
					map
				})
				.values()
				.sum::<i32>();
			println!("{}", reps);
			if acc_max.is_none() || reps > acc_reps {
				(Some(data), reps)
			} else {
				(acc_max, acc_reps)
			}
		}).0.unwrap()
}

#[test]
fn challenge_1() {
	let data = Data::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
	assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", data.as_b64());
}

#[test]
fn challenge_2() {
	let data1 = Data::from_hex("1c0111001f010100061a024b53535009181c");
	let data2 = Data::from_hex("686974207468652062756c6c277320657965");
	println!("{} {}", data1.len(), data2.len());
	assert_eq!("746865206b696420646f6e277420706c6179", (data1 ^ data2).as_hex());
}

#[test]
fn challenge_3() {
	let data = Data::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
	let guess = data.guess_single_byte_xor();
	assert_eq!("Cooking MC's like a pound of bacon", guess.0.as_str().unwrap());
}

#[test]
fn challenge_4() {
	let lines = read_to_string("res/1/4.txt").unwrap();
	let guess: (Option<Data>, i32) = lines.split_ascii_whitespace()
		.fold((None, 0), |acc, line| {
			let data = Data::from_hex(line);
			let guess = data.guess_single_byte_xor();
			if acc.0.is_none() || guess.1 > acc.1 {
				(Some(guess.0), guess.1)
			} else {
				acc
			}
		});
	let guess = (guess.0.unwrap(), guess.1);

	assert_eq!("Now that the party is jumping\n", guess.0.as_str().unwrap());
}

#[test]
fn challenge_5() {
	let data = Data::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
	assert_eq!(
		"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		(data ^ "ICE").as_hex()
	)
}

#[test]
fn challenge_6() {
	assert_eq!(37, Data::from("this is a test").hamming_distance("wokka wokka!!!"));

	let raw_data = read_to_string("res/1/6.txt").unwrap().replace('\n', "");
	let data = Data::from_b64(&raw_data);
	assert_eq!("I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
", data.guess_repeating_key_xor().as_str().unwrap());
}

#[test]
fn challenge_7() {
	let ciphertext = Data::from_b64(&read_to_string("res/1/7.txt").unwrap().replace('\n', ""));
	let plaintext = ciphertext.aes_128_ecb_decrypt("YELLOW SUBMARINE");
	assert_eq!("I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
\u{4}\u{4}\u{4}\u{4}", plaintext.as_str().unwrap());
}

#[test]
fn challenge_8() {
	let file = read_to_string("res/1/8.txt").unwrap();
	let data: Vec<_> = file.split('\n').map(|line| Data::from_hex(line.trim())).collect();
	assert_eq!(
		"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
		detect_aes_128_ecb(&data).as_hex()
	);
}
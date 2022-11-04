use crate::{AesMode, Data};
use rand::prelude::*;

pub fn detect_aes_128_ecb(data_slice: &[Data]) -> &Data {
	data_slice.into_iter()
		.fold((None, 0), |(acc_data, acc_percent), data| {
			let percent = data.aes_128_ecb_percent();
			if acc_data.is_none() || percent > acc_percent {
				(Some(data), percent)
			} else {
				(acc_data, acc_percent)
			}
		}).0.unwrap()
}

pub fn random_key(rand: &mut ThreadRng) -> [u8; 16] {
	let mut key = [0u8; 16];
	rand.fill_bytes(&mut key);
	key
}

pub fn random_encrypt(plaintext: impl Into<Vec<u8>>, mode: Option<AesMode>) -> (Data, AesMode) {
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
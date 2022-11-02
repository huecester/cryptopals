use crate::Data;

#[test]
fn challenge_9() {
	assert_eq!(
		Data::from("YELLOW SUBMARINE").pkcs7_pad(20).as_str().unwrap(),
		"YELLOW SUBMARINE\x04\x04\x04\x04"
	);
}
use std::fs::read_to_string;
use crate::Data;

#[test]
fn challenge_9() {
	assert_eq!(
		Data::from("YELLOW SUBMARINE").pkcs7_pad(20).as_str().unwrap(),
		"YELLOW SUBMARINE\x04\x04\x04\x04"
	);
}

#[test]
fn aes_128_ecb_encrypt_test() {
	let plaintext = Data::from("I'm back and I'm ringin' the bell 
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
\u{4}\u{4}\u{4}\u{4}");
	let ciphertext = plaintext.aes_128_ecb_encrypt("YELLOW SUBMARINE");
	assert_eq!(read_to_string("res/1/7.txt").unwrap().replace('\n', ""), ciphertext.as_b64());
}

#[test]
fn challenge_10() {
	let ciphertext = Data::from_b64(&read_to_string("res/2/10.txt").unwrap().replace('\n', ""));
	let plaintext = ciphertext.aes_128_cbc_decrypt("YELLOW SUBMARINE", [0; 16]);
	assert_eq!("unky music 
\u{4}\u{4}\u{4}\u{4} on 
Play that fn, Come on, Comewhite boy Come oat funky music, der now 
Play thsic A little louay that funky muy it, say it 
Plwhite boy you sahat funky music  me hear 
Play ton, Come on, letunky music Come e. 

Play that fusic till you dilay that funky mand boogie and py, go 
Lay down boy, go white bo music Go white 
play that funkygo white boy go , go white boy,  funky music SaySay -- Play thating this song 

 everybody and song 
So come on,, you're dead wr I was weak, BoyYou thought thatime, anywhere 

attle me -- Anytare 
You wanna band don't be squo come up close dance to cure 
Sor, Ice, do the t the witch doctk and endure 
Lefit, so step bacu're pitchin' a  call me Dad 
Yo to ICE, You canhe lyrics belongbe sad 
'Cause te mad and don't l it 
So don't bo, so I can smels gettin' hot, sl it 
Your body'O! and I can teleakenin' fast, Yyear. 

You're w You, '90 is my 
'89 in my time!end me your ear  step down and light have it 
Sought that 
You me once and I thoc 
You trapped mht like a fanati I'm hangin' tigwn 
Sparkamatic, just gettin' doin' on mine, I'mThere's no tripphittin' ground 
ed by the bases man Nazi 
Startl hard like a Gere. 

Steppin' so by the VIP possow you're amazedhis here song 
Nhetto groovin' tll through the gto sing along 
Agroovin' trying lue 
Movin' and in' like Crazy G freaks are jock 
'Cause why theeople are buyin'ellin' and you pVanilla Ice is srl stop cryin' 
op trying and giino 
So punks ststagger like a wxicating so you ke a rhino 
Intom comin' hard liIce yep, yep, I' 

VIP. Vanilla e on and say it!ith a spoon! Comeat 
Spaghetti wy, you probably  my God, homebodirls 
Soon -- Ohe, no time, no gnowhere, no placr. 

You'll get f you're a loaferfect 
But not iractice makes peOver and over, po get my style 
ll keep tryin' to hang 
But you'', You can try there's no denyinon to Delilah 
Te Samson -- Samsr wet. 

I'm likgirl and make he can take a fly t you can bet 
In effect and thalidocious 
I'm afragilisticexpiacious 
Supercalae my rhymes atrogood luck, I lik some wood 
For 3 Yo -- Knock onsound good 
1-2- up and make it So I can funk itt play through 
d so let the bea
It's off my heawanna listen to Yea the one ya' ay 

Stage 2 -- an any kid n' pl dance better this ok 
And I canove me and that lies sa y they ln phase 
The gired 
I'm in my owno dissin' allow stage 
There's se I control the
So get off 'cauu starin' at me mn, then 
Why yo don't give a dal be 
And if you's the way I wilooth 'cause thatVanilla Go! 

Smide yellin', Go posse's to the sconcepts go 
My it flow, let my in 
To just let  mouth and I beg 
It controls my my drug kick iny. 

I'm lettin' man I'm not laza's on the mike,n' crazy 
Vanill the girlies goiHittin' hard and' all them Z's 
DJ Deshay cuttin
Well that's my  the back of me l 
In ecstasy inhe fly girls yelthe mike while tl 
A rockin' on  ringin' the belI'm back and I'm", plaintext.as_str().unwrap());
}

#[test]
fn aes_128_cbc_encrypt_test() {
	let plaintext = Data::from("unky music 
\u{4}\u{4}\u{4}\u{4} on 
Play that fn, Come on, Comewhite boy Come oat funky music, der now 
Play thsic A little louay that funky muy it, say it 
Plwhite boy you sahat funky music  me hear 
Play ton, Come on, letunky music Come e. 

Play that fusic till you dilay that funky mand boogie and py, go 
Lay down boy, go white bo music Go white 
play that funkygo white boy go , go white boy,  funky music SaySay -- Play thating this song 

 everybody and song 
So come on,, you're dead wr I was weak, BoyYou thought thatime, anywhere 

attle me -- Anytare 
You wanna band don't be squo come up close dance to cure 
Sor, Ice, do the t the witch doctk and endure 
Lefit, so step bacu're pitchin' a  call me Dad 
Yo to ICE, You canhe lyrics belongbe sad 
'Cause te mad and don't l it 
So don't bo, so I can smels gettin' hot, sl it 
Your body'O! and I can teleakenin' fast, Yyear. 

You're w You, '90 is my 
'89 in my time!end me your ear  step down and light have it 
Sought that 
You me once and I thoc 
You trapped mht like a fanati I'm hangin' tigwn 
Sparkamatic, just gettin' doin' on mine, I'mThere's no tripphittin' ground 
ed by the bases man Nazi 
Startl hard like a Gere. 

Steppin' so by the VIP possow you're amazedhis here song 
Nhetto groovin' tll through the gto sing along 
Agroovin' trying lue 
Movin' and in' like Crazy G freaks are jock 
'Cause why theeople are buyin'ellin' and you pVanilla Ice is srl stop cryin' 
op trying and giino 
So punks ststagger like a wxicating so you ke a rhino 
Intom comin' hard liIce yep, yep, I' 

VIP. Vanilla e on and say it!ith a spoon! Comeat 
Spaghetti wy, you probably  my God, homebodirls 
Soon -- Ohe, no time, no gnowhere, no placr. 

You'll get f you're a loaferfect 
But not iractice makes peOver and over, po get my style 
ll keep tryin' to hang 
But you'', You can try there's no denyinon to Delilah 
Te Samson -- Samsr wet. 

I'm likgirl and make he can take a fly t you can bet 
In effect and thalidocious 
I'm afragilisticexpiacious 
Supercalae my rhymes atrogood luck, I lik some wood 
For 3 Yo -- Knock onsound good 
1-2- up and make it So I can funk itt play through 
d so let the bea
It's off my heawanna listen to Yea the one ya' ay 

Stage 2 -- an any kid n' pl dance better this ok 
And I canove me and that lies sa y they ln phase 
The gired 
I'm in my owno dissin' allow stage 
There's se I control the
So get off 'cauu starin' at me mn, then 
Why yo don't give a dal be 
And if you's the way I wilooth 'cause thatVanilla Go! 

Smide yellin', Go posse's to the sconcepts go 
My it flow, let my in 
To just let  mouth and I beg 
It controls my my drug kick iny. 

I'm lettin' man I'm not laza's on the mike,n' crazy 
Vanill the girlies goiHittin' hard and' all them Z's 
DJ Deshay cuttin
Well that's my  the back of me l 
In ecstasy inhe fly girls yelthe mike while tl 
A rockin' on  ringin' the belI'm back and I'm");
	let ciphertext = plaintext.aes_128_cbc_encrypt("YELLOW SUBMARINE", [0; 16]);
	assert_eq!(read_to_string("res/2/10.txt").unwrap().replace('\n', ""), ciphertext.as_b64());
}
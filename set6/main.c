/*
 * main.c for set 6 of the matasano crypto challenges
 *
 *  Created on: 29.10.2014
 *  Author:     rc0r
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/dsa.h"
#include "../include/rsa.h"

int main(int argc, char *argv[])
{
	// seed RNG (in a shitty way)
	// !!proper seeding needed here!!
	unsigned int rseed = time(NULL);
	void *buf = &rseed;
	RAND_seed(buf, 9);

	/**       Set 6 Challenge 41       **/
	/** RSA unpadded msg oracle attack **/
	rsa_unpadded_msg_oracle_attack_test();

	/**       Set 6 Challenge 42       **/
	/** Bleichenbacher e=3 RSA attack **/
	rsa_simple_pad_test();

	rsa_key_t pik, puk;
	unsigned int sign_len;
	unsigned char *sign;
	unsigned char *sign_hex;

	pik.e = BN_new();
	pik.n = BN_new();
	puk.e = BN_new();
	puk.n = BN_new();

	rsa_generate_keypair(&puk, &pik, 512);

	sign_len = rsa_sign(&sign, "hi mom", 6, &pik);

	hex_encode(&sign_hex, sign, sign_len);

	printf("[s6c2] RSA signature (%d bits): %s\n", sign_len*8, sign_hex);

	if(rsa_sign_verify("hi mom", 6, sign, sign_len, &puk)) {
		printf("[s6c2] RSA signature successfully verified!\n");
	} else {
		printf("[s6c2] RSA signature *NOT* verified!\n");
	}

	free(sign_hex);

	unsigned char *forged_sign = NULL;
	unsigned int forged_sign_len = 0;

	forged_sign_len = rsa_sign_forge(&forged_sign, "hi mom", 6, &puk);

	sign_len = hex_encode(&sign_hex, forged_sign, forged_sign_len);

	printf("[s6c2] Forged RSA signature (%d bits): %s\n", sign_len*8, sign_hex);

	if(rsa_sign_verify("hi mom", 6, forged_sign, forged_sign_len, &puk)) {
		printf("[s6c2] Forged RSA signature successfully verified!\n");
	} else {
		printf("[s6c2] Forged RSA signature *NOT* verified!\n");
	}

	free(forged_sign);
	free(sign_hex);
	free(sign);

	/**      Set 6 Challenge 43     **/
	/** DSA key recovery from nonce **/
	unsigned char sha1sum[41];
	unsigned char *test_msg = "For those that envy a MC it can be hazardous to your health\n\
So be friendly, a matter of life and death, just like a etch-a-sketch\n";

	hash_sha1(sha1sum, test_msg, strlen(test_msg));

	printf("[s6c3] sha1() = %s\n", sha1sum);

	dsa_key_t dsa_puk;
	dsa_key_t dsa_pik;
	dsa_signature_t dsa_sign;

	dsa_puk.g = BN_new();
	dsa_puk.p = BN_new();
	dsa_puk.q = BN_new();
	dsa_puk.xy = BN_new();

	dsa_pik.g = BN_new();
	dsa_pik.p = BN_new();
	dsa_pik.q = BN_new();
	dsa_pik.xy = BN_new();

	dsa_sign.r = BN_new();
	dsa_sign.s = BN_new();

	dsa_generate_keypair(&dsa_puk, &dsa_pik, 256);
	dsa_sha1_sign(&dsa_sign, test_msg, strlen(test_msg), &dsa_pik);
	if(dsa_sha1_sign_verify(test_msg, strlen(test_msg), &dsa_sign, &dsa_puk)) {
		printf("[s6c3] DSA-SHA1 signature successfully verified!\n");
	} else {
		printf("[s6c3] DSA-SHA1 signature *NOT* verified!\n");
	}

	BN_hex2bn(&dsa_puk.xy, "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
bab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
bb283e6633451e535c45513b2d33c99ea17");
	BN_dec2bn(&dsa_sign.r, "548099063082341131477253921760299949438196259240");
	BN_dec2bn(&dsa_sign.s, "857042759984254168557880549501802188789837994940");

//	BN_print_fp(stdout, dsa_sign.s);
//	printf("\n");

//	BN_dec2bn(&dsa_puk.g, "60");
//	BN_dec2bn(&dsa_puk.p, "283");
//	BN_dec2bn(&dsa_puk.q, "47");
//	BN_dec2bn(&dsa_puk.xy, "158");
//
//	BN_dec2bn(&dsa_sign.r, "19");
//	BN_dec2bn(&dsa_sign.s, "30");

	if(dsa_calc_private_key_from_k(&dsa_pik, &dsa_sign, 65536, test_msg, strlen(test_msg), &dsa_puk)) {
		unsigned char *dsa_pik_hex = BN_bn2hex(dsa_pik.xy);
		unsigned int i;

		// convert to lower case
		for(i=0; i<strlen(dsa_pik_hex); i++) {
			dsa_pik_hex[i] = tolower(dsa_pik_hex[i]);
		}
		printf("[s6c3] DSA private key: %s\n", dsa_pik_hex);

		unsigned char dsa_pik_hex_sha1[SHA_DIGEST_LENGTH*2+1];
		hash_sha1(dsa_pik_hex_sha1, dsa_pik_hex, strlen(dsa_pik_hex));
		printf("[s6c3] SHA1(private key): %s\n", dsa_pik_hex_sha1);

		OPENSSL_free(dsa_pik_hex);
	} else {
		printf("[s6c3] DSA private key *NOT* found!\n");
	}

	dsa_signature_free(&dsa_sign);

	/**   Set 6 Challenge 44    **/
	/** DSA nonce recovery from **/
	/**     repeated nonce     **/
	dsa_signature_t sigs[11];
	// input messages
	unsigned char *msgs[] = {
			"Listen for me, you better listen for me now. ",
			"Listen for me, you better listen for me now. ",
			"When me rockin' the microphone me rock on steady, ",
			"Yes a Daddy me Snow me are de article dan. ",
			"But in a in an' a out de dance em ",
			"Aye say where you come from a, ",
			"People em say ya come from Jamaica, ",
			"But me born an' raised in the ghetto that I want yas to know, ",
			"Pure black people mon is all I mon know. ",
			"Yeah me shoes a an tear up an' now me toes is a show a ",
			"Where me a born in are de one Toronto, so "
	};
	// coresponding SHA1 hashes for msgs
	unsigned char *hashes[] = {
			"a4db3de27e2db3e5ef085ced2bced91b82e0df19",
			"a4db3de27e2db3e5ef085ced2bced91b82e0df19",
			"21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4",
			"1d7aaaa05d2dee2f7dabdc6fa70b6ddab9c051c5",
			"6bc188db6e9e6c7d796f7fdd7fa411776d7a9ff",
			"5ff4d4e8be2f8aae8a5bfaabf7408bd7628f43c9",
			"7d9abd18bbecdaa93650ecc4da1b9fcae911412",
			"88b9e184393408b133efef59fcef85576d69e249",
			"d22804c4899b522b23eda34d2137cd8cc22b9ce8",
			"bc7ec371d951977cba10381da08fe934dea80314",
			"d6340bfcda59b6b75b59ca634813d572de800e8f"
	};
	// signature r values for msgs
	unsigned char *sig_r[] = {
			"1105520928110492191417703162650245113664610474875",
			"51241962016175933742870323080382366896234169532",
			"228998983350752111397582948403934722619745721541",
			"1099349585689717635654222811555852075108857446485",
			"425320991325990345751346113277224109611205133736",
			"486260321619055468276539425880393574698069264007",
			"537050122560927032962561247064393639163940220795",
			"826843595826780327326695197394862356805575316699",
			"1105520928110492191417703162650245113664610474875",
			"51241962016175933742870323080382366896234169532",
			"228998983350752111397582948403934722619745721541"
	};
	// signature s values for msgs
	unsigned char *sig_s[] = {
			"1267396447369736888040262262183731677867615804316",
			"29097472083055673620219739525237952924429516683",
			"277954141006005142760672187124679727147013405915",
			"1013310051748123261520038320957902085950122277350",
			"203941148183364719753516612269608665183595279549",
			"502033987625712840101435170279955665681605114553",
			"1133410958677785175751131958546453870649059955513",
			"559339368782867010304266546527989050544914568162",
			"1021643638653719618255840562522049391608552714967",
			"506591325247687166499867321330657300306462367256",
			"458429062067186207052865988429747640462282138703"
	};

	unsigned int i, j;
	int identical_nonce[11];

	// init
	BN_hex2bn(&dsa_puk.xy, "2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
2971c3de5084cce04a2e147821");

	for(i=0; i<11; i++) {
		sigs[i].r = BN_new();
		sigs[i].s = BN_new();
		BN_dec2bn(&(sigs[i].r), sig_r[i]);
		BN_dec2bn(&(sigs[i].s), sig_s[i]);
		identical_nonce[i] = -1;
	}

	// build array containing info about reused nonces
	for(i=0; i<10; i++) {
		for(j=i+1; j<11; j++) {
			if(!dsa_sign_nonce_cmp(&sigs[i], &sigs[j])) {
				identical_nonce[i] = j;
				break;
			}
		}
//		printf("[s6c4] id[%02d] = %02d\n", i, identical_nonce[i]);
	}

	// free
	for(i=0; i<11; i++) {
		dsa_signature_free(&sigs[i]);
	}

	dsa_key_free(&dsa_puk);
	dsa_key_free(&dsa_pik);

	return 0;
}

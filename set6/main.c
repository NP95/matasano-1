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

	unsigned char sha1sum[41];
	unsigned char *test_msg = "For those that envy a MC it can be hazardous to your health\n\
So be friendly, a matter of life and death, just like a etch-a-sketch\n";

	hash_sha1(sha1sum, test_msg, strlen(test_msg));

	printf("[s6c3] sha1() = %s\n", sha1sum);

	dsa_key_t dsa_puk;// = dsa_key_new();
	dsa_key_t dsa_pik;// = dsa_key_new();
	dsa_signature_t dsa_sign;// = dsa_signature_new();

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

	dsa_signature_free(&dsa_sign);
	dsa_key_free(&dsa_puk);
	dsa_key_free(&dsa_pik);

	return 0;
}

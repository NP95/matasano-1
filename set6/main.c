/*
 * main.c for set 6 of the matasano crypto challenges
 *
 *  Created on: 29.10.2014
 *  Author:     rc0r
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/rsa.h"

int main(int argc, char *argv[])
{
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

	rsa_generate_keypair(&puk, &pik, 1024);

	sign_len = rsa_sign(&sign, "Hey hey, my my!!", 16, &pik);

	hex_encode(&sign_hex, sign, sign_len);

	printf("[s6c2] rsa signature: %s\n", sign_hex);

	free(sign_hex);
	free(sign);

	return 0;
}

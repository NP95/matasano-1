#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/dh.h"

int main(int argc, char *argv[])
{
	/** SET 5 CHALLENGE 33 **/
	/**  DH KEY EXCHANGE   **/
	// small int
	unsigned long a, A, b, B, s1, s2;

	srand(time(NULL));

	dh_generate_keypair_smallint(&a, &A);
	dh_generate_keypair_smallint(&b, &B);

	s1 = dh_generate_session_key_smallint(a, B);
	s2 = dh_generate_session_key_smallint(b, A);

	printf("[s5c1] *smallint* a = %ld, A = %ld, b = %ld, B = %ld, s = %ld ?= %ld\n", a, A, b, B, s1, s2);

	// bigint
	BIGNUM p, g;
	BIGNUM ba, bA, bb, bB, bs1, bs2;

	dh_init(&p, &g);

	BN_init(&ba);
	BN_init(&bA);
	BN_init(&bb);
	BN_init(&bB);
	BN_init(&bs1);
	BN_init(&bs2);

	unsigned char c_s1[20], c_s2[20];
	unsigned int i;

	dh_generate_keypair(&ba, &bA, &g, &p);
	dh_generate_keypair(&bb, &bB, &g, &p);
	dh_generate_session_key(c_s1, &bs1, &ba, &bB, &p);
	dh_generate_session_key(c_s2, &bs2, &bb, &bA, &p);

	printf("[s5c1] *bignum* s1 = {\n");
// 	BN_print_fp(stdout, &bs1);
	for(i=0; i<20; i++)
		printf("%02x", c_s1[i]);
	printf("\n}\n[s5c1] *bignum* s2 = {\n");
// 	BN_print_fp(stdout, &bs2);
	for(i=0; i<20; i++)
		printf("%02x", c_s2[i]);
	printf("\n}\n");

	dh_clear(&p, &g);

	return 0;
}

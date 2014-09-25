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

	printf("[s5c1] *bignum* s1 = '");
// 	BN_print_fp(stdout, &bs1);
	for(i=0; i<20; i++)
		printf("%02x", c_s1[i]);
	printf("'\n[s5c1] *bignum* s2 = '");
// 	BN_print_fp(stdout, &bs2);
	for(i=0; i<20; i++)
		printf("%02x", c_s2[i]);
	printf("'\n");

	/**  SET 5 CHALLENGE 34  **/
	/** DH-KE FIXED KEY MITM **/

	unsigned char c_p[1024];
	unsigned char c_g[1024];
	unsigned char c_A[1024];
	unsigned char c_B[1024];

	BN_init(&ba);
	BN_init(&bA);

	// M -> B: p, g, p
	printf("[s5c2] M -> B: p, g, p\n");
	dhke_initiate(c_p, c_g, c_A, &ba, &bA, &p, &g);

	// M -> A: p
	printf("[s5c2] M -> A: p\n");
// 	dhke_initiate_reply(c_B, c_p, c_g, c_A, c_s2);
	dhke_initiate_reply(c_B, c_p, c_g, c_p, c_s2);

	// A -> B: cmsg, iv
// 	dhke_initiate_finalize(c_s1, c_B, &ba, &p);
	dhke_initiate_finalize(c_s1, c_p, &ba, &p);

	printf("[s5c2] *bignum* s1 = '");
	for(i=0; i<20; i++)
		printf("%02x", c_s1[i]);
	printf("'\n[s5c2] *bignum* s2 = '");
	for(i=0; i<20; i++)
		printf("%02x", c_s2[i]);
	printf("'\n");

	unsigned char *plain_in = "YELLOW SUBMARINE";
	unsigned char p_out[128];
	unsigned char c_out[128];
	unsigned char iv[16];
	unsigned int c_len, p_len;

	c_len = dhke_session_send(c_out, iv, plain_in, 16, c_s1);
	printf("[s5c2] A -> B: cmsg = '");
	for(i=0; i<c_len; i++) {
		printf("%02x", c_out[i]);
	}
	printf("', iv\n");

	// perform attack as M
	unsigned char m_out[128];
	unsigned char obuf[20];

	// M knows s = 0 and calculates session key = SHA1(0)
	SHA1("", 0, obuf);
	printf("[s5c2] M: sess_key = '");
	for(i=0; i<20; i++) {
		printf("%02x", obuf[i]);
	}
	printf("'\n");

	// M performs decryption
	aes_cbc_decrypt(128, m_out, c_out, c_len, obuf, iv);
	printf("[s5c2] M decrypts msg='%s'\n", m_out);

	// B performs decryption
	p_len = dhke_session_recv(p_out, c_out, c_len, c_s2, iv);

	printf("[s5c2] B recvd: msg = '%s'\n", p_out);

	dh_clear(&p, &g);

	return 0;
}

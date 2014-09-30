#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/dh.h"
#include "../include/srp.h"

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

	BN_init(&g);
	BN_init(&p);
	BN_init(&ba);
	BN_init(&bA);
	BN_init(&bb);
	BN_init(&bB);
	BN_init(&bs1);
	BN_init(&bs2);

	unsigned char c_s1[20], c_s2[20];
	unsigned int i;

	dh_init(&p, &g);
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

	// M performs decryption
	dhke_attack_zero_session_key(m_out, c_out, c_len, iv);
	printf("[s5c2] M decrypts msg='%s'\n", m_out);

	// B performs decryption
	p_len = dhke_session_recv(p_out, c_out, c_len, c_s2, iv);

	printf("[s5c2] B recvd: msg = '%s'\n", p_out);

	/**   SET 5 CHALLENGE 35   **/
	/** DH-KE MALICIOUS G MITM **/
	memset(c_g, 0, 1024);
	memset(c_p, 0, 1024);
	memset(c_A, 0, 1024);
	memset(c_B, 0, 1024);
	memset(c_out, 0, 128);
	memset(m_out, 0, 128);

	BIGNUM bn1, g2;

	BN_init(&ba);
	BN_init(&bA);
	BN_init(&bn1);
	BN_init(&g2);

	// prepare malicious g'
	// g' = 0; --> perform dhke_attack_zero_session_key()
// 	printf("[s5c3] M sets g' = 0\n");
// 	BN_zero(&g2);
	// g' = p --> perform dhke_attack_zero_session_key()
// 	printf("[s5c3] M sets g' = p\n");
// 	BN_copy(&g2, &p);
	// g' = p-1
	printf("[s5c3] M sets and distributes g' = p-1\n");
	BN_one(&bn1);
	BN_sub(&g2, &p, &bn1);

	// M -> B: p, g', A'
	printf("[s5c3] A -> B: A'\n");
	dhke_initiate(c_p, c_g, c_A, &ba, &bA, &p, &g2);

	// M -> A: B'
	printf("[s5c3] B -> A: B'\n");
	dhke_initiate_reply(c_B, c_p, c_g, c_A, c_s2);

	// A -> B: cmsg, iv
	dhke_initiate_finalize(c_s1, c_B, &ba, &p);

	c_len = dhke_session_send(c_out, iv, plain_in, 16, c_s1);
	printf("[s5c3] A -> B: cmsg = '");
	for(i=0; i<c_len; i++) {
		printf("%02x", c_out[i]);
	}
	printf("', iv\n");

	// M performs decryption
	// use for: g' = 0, g' = p
// 	dhke_attack_zero_session_key(m_out, c_out, c_len, iv);
	// use for g' = p-1
	dhke_attack_p_1_session_key(m_out, c_out, c_len, c_A, c_B, iv);
	printf("[s5c3] M decrypts msg='%s'\n", m_out);

	// B performs decryption
	p_len = dhke_session_recv(p_out, c_out, c_len, c_s2, iv);

	printf("[s5c3] B recvd: msg = '%s'\n", p_out);

	/**   SET 5 CHALLENGE 36   **/
	/** SECURE REMOTE PASSWORD **/
	unsigned char srp_salt[9];
	unsigned char *srp_pass = "GDFTHR OF GRUNGE"; // 16

	BIGNUM v, sS, cS;
	BN_init(&v);
	BN_init(&ba);
	BN_init(&bA);
	BN_init(&bb);
	BN_init(&bB);
	BN_init(&cS);
	BN_init(&sS);

	srp_server_init(srp_salt, &v, &bb, &bB, srp_pass, &g, &p);
	srp_client_init(&ba, &bA, &g, &p);

	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];

	printf("server calc S\n");
	srp_server_calc_session_key(str_hash, &sS, &bA, &bb, &bB, &v, &p);
	printf("[s5c4] server: sha256(S) = %s\n", str_hash);
	
	memset(str_hash, 0, 2*SHA256_DIGEST_LENGTH);
	printf("client calc S\n");
	srp_client_calc_session_key(str_hash, &cS, srp_salt, srp_pass, &ba, &bA, &bB, &g, &p);
	printf("[s5c4] client: sha256(S) = %s\n", str_hash);

// 	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];
// 	srp_generate_salted_password_hash(&v, str_hash, srp_salt, srp_pass);

	dh_clear(&p, &g);

// 	BN_free(&p);
// 	BN_free(&g);
// 	BN_free(&ba);
// 	BN_free(&bA);
// 	BN_free(&bb);
// 	BN_free(&bB);
// 	BN_free(&bs1);
// 	BN_free(&bs2);
// 	BN_free(&v);
// 	BN_free(&cS);
// 	BN_free(&sS);
// 	BN_free(&bn1);
// 	BN_free(&g2);
	return 0;
}

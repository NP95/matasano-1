#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>

#include "../include/dh.h"
#include "../include/mac.h"
#include "../include/rsa.h"
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
	BIGNUM *p, *g;
	BIGNUM *ba, *bA, *bb, *bB, *bs1, *bs2;

	g = BN_new();
	p = BN_new();
	ba = BN_new();
	bA = BN_new();
	bb = BN_new();
	bB = BN_new();
	bs1 = BN_new();
	bs2 = BN_new();

	unsigned char c_s1[20], c_s2[20];
	unsigned int i;

	dh_init(p, g);
	dh_generate_keypair(ba, bA, g, p);
	dh_generate_keypair(bb, bB, g, p);
	dh_generate_session_key(c_s1, bs1, ba, bB, p);
	dh_generate_session_key(c_s2, bs2, bb, bA, p);

	printf("[s5c1] *bignum* s1 = '");
// 	BN_print_fp(stdout, &bs1);
	for(i=0; i<20; i++)
		printf("%02x", c_s1[i]);
	printf("'\n[s5c1] *bignum* s2 = '");
// 	BN_print_fp(stdout, &bs2);
	for(i=0; i<20; i++)
		printf("%02x", c_s2[i]);
	printf("'\n");

	BN_free(ba);
	BN_free(bA);
	BN_free(bb);
	BN_free(bB);
	BN_free(bs1);
	BN_free(bs2);

	/**  SET 5 CHALLENGE 34  **/
	/** DH-KE FIXED KEY MITM **/
	unsigned char c_p[1024];
	unsigned char c_g[1024];
	unsigned char c_A[1024];
	unsigned char c_B[1024];

	ba = BN_new();
	bA = BN_new();

	// M -> B: p, g, p
	printf("[s5c2] M -> B: p, g, p\n");
	dhke_initiate(c_p, c_g, c_A, ba, bA, p, g);

	// M -> A: p
	printf("[s5c2] M -> A: p\n");
// 	dhke_initiate_reply(c_B, c_p, c_g, c_A, c_s2);
	dhke_initiate_reply(c_B, c_p, c_g, c_p, c_s2);

	// A -> B: cmsg, iv
// 	dhke_initiate_finalize(c_s1, c_B, &ba, &p);
	dhke_initiate_finalize(c_s1, c_p, ba, p);

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

	BN_free(ba);
	BN_free(bA);
	/**   SET 5 CHALLENGE 35   **/
	/** DH-KE MALICIOUS G MITM **/
	memset(c_g, 0, 1024);
	memset(c_p, 0, 1024);
	memset(c_A, 0, 1024);
	memset(c_B, 0, 1024);
	memset(c_out, 0, 128);
	memset(m_out, 0, 128);

	BIGNUM *bn1, *g2;

	ba = BN_new();
	bA = BN_new();
	bn1 = BN_new();
	g2 = BN_new();

	// prepare malicious g'
	// g' = 0; --> perform dhke_attack_zero_session_key()
// 	printf("[s5c3] M sets g' = 0\n");
// 	BN_zero(&g2);
	// g' = p --> perform dhke_attack_zero_session_key()
// 	printf("[s5c3] M sets g' = p\n");
// 	BN_copy(&g2, &p);
	// g' = p-1
	printf("[s5c3] M sets and distributes g' = p-1\n");
	BN_one(bn1);
	BN_sub(g2, p, bn1);

	// M -> B: p, g', A'
	printf("[s5c3] A -> B: A'\n");
	dhke_initiate(c_p, c_g, c_A, ba, bA, p, g2);

	// M -> A: B'
	printf("[s5c3] B -> A: B'\n");
	dhke_initiate_reply(c_B, c_p, c_g, c_A, c_s2);

	// A -> B: cmsg, iv
	dhke_initiate_finalize(c_s1, c_B, ba, p);

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

	BN_free(ba);
	BN_free(bA);
	BN_free(bn1);
	BN_free(g2);

	/**   SET 5 CHALLENGE 36   **/
	/** SECURE REMOTE PASSWORD **/
	unsigned char srp_salt[9];
	unsigned char *srp_pass = "GDFTHR OF GRUNGE"; // 16
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH+1];
	unsigned char hmac_s[SHA256_DIGEST_LENGTH];
	unsigned int hmac_s_len;
	unsigned char hmac_c[SHA256_DIGEST_LENGTH];
	unsigned int hmac_c_len;

	BIGNUM *v, *sS, *cS;
	v = BN_new();
	ba = BN_new();
	bA = BN_new();
	bb = BN_new();
	bB = BN_new();
	cS = BN_new();
	sS = BN_new();

	memset(srp_salt, 0, 9);
	srp_server_init(srp_salt, v, bb, bB, srp_pass, g, p);
	srp_client_init(ba, bA, g, p);

// 	printf("server calc S\n");
	srp_server_calc_session_key(str_hash, sS, bA, bb, bB, v, p);
// 	printf("[s5c4] server: sha256(S) = %s\n", str_hash);
	// calc HMAC_SHA256(&cS, salt)
	hmac_s_len = sha256_secret_prefix_mac(hmac_s, str_hash, strlen(str_hash), srp_salt, strlen(srp_salt));
	
	memset(str_hash, 0, 2*SHA256_DIGEST_LENGTH+1);
	srp_client_calc_session_key(str_hash, cS, srp_salt, srp_pass, ba, bA, bB, g, p);
// 	printf("[s5c4] client: sha256(S) = %s\n", str_hash);
	// calc HMAC_SHA256(&cS, salt)
	hmac_c_len = sha256_secret_prefix_mac(hmac_c, str_hash, strlen(str_hash), srp_salt, strlen(srp_salt));

	printf("[s5c4] server: HMAC(K,Salt) = ");
	for(i=0; i<hmac_s_len; i++) {
		printf("%02x", hmac_s[i]);
	}
	printf("\n");

	printf("[s5c4] client: HMAC(K,Salt) = ");
	for(i=0; i<hmac_c_len; i++) {
		printf("%02x", hmac_c[i]);
	}
	printf("\n");

	if((hmac_s_len == hmac_c_len) && !strncmp(hmac_s, hmac_c, hmac_s_len))
		printf("[s5c4] server: Client HMAC-SHA256 successfully validated!\n");
	else
		printf("[s5c4] server: Client HMAC-SHA256 *NOT* validated!\n");

	BN_free(v);
	BN_free(ba);
	BN_free(bA);
	BN_free(bb);
	BN_free(bB);
	BN_free(cS);
	BN_free(sS);

	/**   SET 5 CHALLENGE 37   **/
	/** SRP MALICIOUS A ATTACK **/
	// we're skipping the networking part here and just call the simulator
	// functions from srp.c
	ba = BN_new();
	bA = BN_new();
	bb = BN_new();
	bB = BN_new();
	sS = BN_new();
	cS = BN_new();
	v = BN_new();

	srp_server_init(srp_salt, v, bb, bB, srp_pass, g, p);
	srp_client_init(ba, bA, g, p);

	// now modify A (bA) to be 0, N, c*N
// 	BN_zero(bA);	// A = 0
	BN_copy(bA, p);	// A = N (doesn't matter if we use N, 2*N, c*N)

	// send to server and let server do its calculations
	srp_server_calc_session_key(str_hash, sS, bA, bb, bB, v, p);
// 	printf("[s5c5] server: sha256(S=0) = %s\n", str_hash);
	// calc HMAC_SHA256(&cS, salt)
	hmac_s_len = sha256_secret_prefix_mac(hmac_s, str_hash, strlen(str_hash), srp_salt, strlen(srp_salt));
	
	// client now authenticates with HMAC_SHA256(K=SHA256(S=0), salt)
	// K=SHA256(S=0)
	srp_generate_salted_password_hash(cS, str_hash, "", "0");
// 	printf("[s5c5] client: sha256(S=0) = %s\n", str_hash);
	// calc HMAC_SHA256(K, salt)
	hmac_c_len = sha256_secret_prefix_mac(hmac_c, str_hash, strlen(str_hash), srp_salt, strlen(srp_salt));
	
	printf("[s5c5] server: HMAC(K,Salt) = ");
	for(i=0; i<hmac_s_len; i++) {
		printf("%02x", hmac_s[i]);
	}
	printf("\n");

	printf("[s5c5] client: HMAC(K,Salt) = ");
	for(i=0; i<hmac_c_len; i++) {
		printf("%02x", hmac_c[i]);
	}
	printf("\n");

	if((hmac_s_len == hmac_c_len) && !strncmp(hmac_s, hmac_c, hmac_s_len))
		printf("[s5c5] server: forged client HMAC-SHA256 successfully validated!\n");
	else
		printf("[s5c5] server: forged client HMAC-SHA256 *NOT* validated!\n");

	BN_free(ba);
	BN_free(bA);
	BN_free(bb);
	BN_free(bB);
	BN_free(sS);
	BN_free(cS);
	BN_free(v);

	/**       SET 5 CHALLENGE 38        **/
	/** SSRP OFFLINE DICTIONARY ATTACK **/
	BIGNUM *u, *fb, *fB;

	u = BN_new();
	v = BN_new();
	ba = BN_new();
	bA = BN_new();
	bb = BN_new();
	bB = BN_new();
	cS = BN_new();
	sS = BN_new();
	fb = BN_new();
	fB = BN_new();

	memset(srp_salt, 0, 9*sizeof(unsigned char));

	ssrp_server_init(srp_salt, v, bb, bB, u, srp_pass, g, p);
	ssrp_client_init(ba, bA, g, p);

	ssrp_server_calc_session_key(str_hash, sS, bA, bb, u, v, p);
// 	printf("[s5c6] server: sha256(S=0) = %s\n", str_hash);
	// calc HMAC_SHA256(&cS, salt)
	hmac_s_len = sha256_secret_prefix_mac(hmac_s, str_hash, strlen(str_hash), srp_salt, strlen(srp_salt));
	
	memset(str_hash, 0, 2*SHA256_DIGEST_LENGTH);
	// original settings transmitted to client
// 	ssrp_client_calc_session_key(str_hash, cS, srp_salt, srp_pass, ba, bB, u, p);
	// forged settings transmitted to client:
	// u = 1, b = 1, B=g=2, salt=""
	BN_one(u);
	BN_one(fb);
	BN_copy(fB, g);
	ssrp_client_calc_session_key(str_hash, cS, "", srp_pass, ba, fB, u, p);
// 	printf("[s5c6] client: sha256(S) = %s\n", str_hash);
	// calc HMAC_SHA256(&cS, salt)
	hmac_c_len = sha256_secret_prefix_mac(hmac_c, str_hash, strlen(str_hash), "", 0);

// 	printf("[s5c6] server: HMAC(K,Salt) = ");
// 	for(i=0; i<hmac_s_len; i++) {
// 		printf("%02x", hmac_s[i]);
// 	}
// 	printf("\n");

	printf("[s5c6] client: HMAC(K,\"\") = ");
	for(i=0; i<hmac_c_len; i++) {
		printf("%02x", hmac_c[i]);
	}
	printf("\n");

	// perform offline dictionary attack
	char pass[1024];
	if(ssrp_dictionary_attack(pass, hmac_c, "dict.txt", bA, g, p)>0)
		printf("[s5c6] Password cracked: '%s'\n", pass);
	else
		printf("[s5c6] Password not cracked!\n");

// 	if((hmac_s_len == hmac_c_len) && !strncmp(hmac_s, hmac_c, hmac_s_len))
// 		printf("[s5c6] server: Client HMAC-SHA256 successfully validated!\n");
// 	else
// 		printf("[s5c6] server: Client HMAC-SHA256 *NOT* validated!\n");

	dh_clear(p, g);

	BN_free(p);
	BN_free(g);
	BN_free(ba);
	BN_free(bA);
	BN_free(bb);
	BN_free(bB);
	BN_free(u);
	BN_free(v);
	BN_free(cS);
	BN_free(sS);
	BN_free(fb);
	BN_free(fB);

	/** SET 5 CHALLENGE 39 **/
	/**        RSA         **/
	BIGNUM *egcd_a = BN_new();
	BIGNUM *egcd_b = BN_new();
	BIGNUM *minv   = BN_new();

	egcd_result_t res;

	res.a = BN_new();
	res.u = BN_new();
	res.v = BN_new();

	BN_dec2bn(&egcd_a, "3120");
	BN_dec2bn(&egcd_b, "17");
	//egcd(&res, egcd_a, egcd_b);

	BIO *out = NULL;
	out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	/*printf("[s5c7] egcd.a = ");
	BN_print(out, res.a);
	printf("\n[s5c7] egcd.u = ");
	BN_print(out, res.u);
	printf("\n[s5c7] egcd.v = ");
	BN_print(out, res.v);
	printf("\n");*/

	if(!inv_mod(minv, egcd_a, egcd_b)) {
		printf("[s5c7] inv_mod = ");
		BN_print(out, minv);
		printf("\n");
	} else {
		printf("[s5c7] No inverse found!\n");
	}

	BN_free(egcd_a);
	BN_free(egcd_b);
	BN_free(res.a);
	BN_free(res.u);
	BN_free(res.v);

	// Testing RSA core functions
	rsa_key_t puk;
	rsa_key_t pik;

	puk.e = BN_new();
	puk.n = BN_new();
	pik.e = BN_new();
	pik.n = BN_new();

	BIGNUM *BN_plain = BN_new();
	BIGNUM *BN_crypt = BN_new();

	BN_hex2bn(&BN_plain, "31337");

	printf("[s5c7] BN_plain = ");
	BN_print(out, BN_plain);
	rsa_generate_keypair(&puk, &pik, 128);
	rsa_bn_encrypt(BN_crypt, BN_plain, &puk);
	printf("\n[s5c7] BN_crypt = ");
	BN_print(out, BN_crypt);
	rsa_bn_decrypt(BN_plain, BN_crypt, &pik);
	printf("\n[s5c7] BN_plain'= ");
	BN_print(out, BN_plain);
	printf("\n");

	BN_free(BN_plain);
	BN_free(BN_crypt);

	// Testing RSA 'wrapper' funcs
	unsigned char *rsa_plain_in = "Hello RSA World!";
	unsigned char *rsa_crypt = NULL; // = malloc(1024);
	unsigned int rsa_crypt_len = 0;
	unsigned char *rsa_plain_out = NULL; // = malloc(1024);
	unsigned int rsa_plain_len;

	rsa_crypt_len = rsa_encrypt(&rsa_crypt, rsa_plain_in, 16, &puk);
	rsa_plain_len = rsa_decrypt(&rsa_plain_out, rsa_crypt, rsa_crypt_len, &pik);
	//rsa_plain_out[rsa_plain_len-1] = 0;

	printf("[s5c7] Encrypting '%s' using RSA...\n[s5c7] RSA crypted:   '", rsa_plain_in);
	for(i=0; i<rsa_crypt_len; i++) {
		printf("%02x", rsa_crypt[i]);
	}
	printf("'\n[s5c7] RSA decrypted: '%s'\n", rsa_plain_out);

	free(rsa_crypt);
	free(rsa_plain_out);

	BN_free(puk.e);
	BN_free(puk.n);
	BN_free(pik.e);
	BN_free(pik.n);

	BIO_free(out);

	return 0;
}

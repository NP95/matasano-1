#include <string.h>

#include "../include/aes.h"
#include "../include/dh.h"
#include "../include/rmath.h"

/** SMALL NUM FUNCS **/
void dh_generate_keypair_smallint(unsigned long *priv_key, unsigned long *pub_key)
{
	unsigned long a = rand() % p_smallint;
	(*priv_key) = a;

	(*pub_key) = modexp(g_smallint, a, p_smallint);
}

unsigned long dh_generate_session_key_smallint(unsigned long local_priv_key, unsigned long remote_pub_key)
{
	return modexp(remote_pub_key, local_priv_key, p_smallint);
}

/** BIG NUM FUNCS **/
void dh_init(BIGNUM *p, BIGNUM *g)
{
	BN_init(p);
	BN_init(g);

	if(BN_hex2bn(&p, BN_p_str)==0)
		printf("Error: dh_init(): BN_hex2bn()!\n");

	if(BN_hex2bn(&g, BN_g_str)==0)
		printf("Error: dh_init(): BN_hex2bn()!\n");

	// initialize OpenSSL RNG (in a shitty way)
	while(RAND_status()==0) {
		unsigned int t = (unsigned int) time(NULL);
		RAND_seed(&t, 4);
	}
}

void dh_clear(BIGNUM *p, BIGNUM *g)
{
	BN_clear(p);
	BN_clear(g);
}

void dh_generate_keypair(BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *g, BIGNUM *p)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_init(ctx);

	BN_rand_range(priv_key, p);
	BN_mod_exp(pub_key, g, priv_key, p, ctx);

	BN_CTX_free(ctx);
}

void dh_generate_session_key(unsigned char *c_session_key, BIGNUM *session_key, BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *p)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_init(ctx);

	BN_mod_exp(session_key, pub_key, priv_key, p, ctx);

	unsigned int len = BN_num_bytes(session_key);
	unsigned char sess_bignum[2*len];
	strncpy(sess_bignum, BN_bn2hex(session_key), 2*len);
// 	printf("sess_key(%d) = '%s'\n", len, sess_bignum);
	SHA1(sess_bignum, 2*len, c_session_key);

	BN_CTX_free(ctx);
}

void dhke_initiate(unsigned char *c_p, unsigned char *c_g, unsigned char *c_pub_key, BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *p, BIGNUM *g)
{
	unsigned int len_p, len_g, len_pubk;
	len_p = BN_num_bytes(p);
	len_g = BN_num_bytes(g);
	strncpy(c_p, BN_bn2hex(p), 2*len_p);
	strncpy(c_g, BN_bn2hex(g), 2*len_g);

	dh_generate_keypair(priv_key, pub_key, g, p);

	len_pubk = BN_num_bytes(pub_key);
	strncpy(c_pub_key, BN_bn2hex(pub_key), 2*len_pubk);
}

void dhke_initiate_finalize(unsigned char *sess_key, unsigned char *pub_key_reply, BIGNUM *priv_key, BIGNUM *p)
{
	BIGNUM s, B, *B2;

	BN_init(&B);
	BN_init(&s);

	B2 = &B;

	BN_hex2bn(&B2, pub_key_reply);

	dh_generate_session_key(sess_key, &s, priv_key, &B, p);

	BN_clear(&B);
	BN_clear(&s);
}

void dhke_initiate_reply(unsigned char *pub_key_reply, unsigned char *c_p, unsigned char *c_g, unsigned char *pub_key_init, unsigned char *sess_key)
{
	BIGNUM b, B, A, *A2, s, p, *p2, g, *g2;
	BN_init(&b);
	BN_init(&B);
	BN_init(&A);
	BN_init(&s);
	BN_init(&p);
	BN_init(&g);

	p2 = &p;
	g2 = &g;
	A2 = &A;

	BN_hex2bn(&p2, c_p);
	BN_hex2bn(&g2, c_g);

	dh_generate_keypair(&b, &B, &g, &p);

	unsigned int len = BN_num_bytes(&B);
	strncpy(pub_key_reply, BN_bn2hex(&B), 2*len);
	BN_hex2bn(&A2, pub_key_init);

	dh_generate_session_key(sess_key, &s, &b, &A, &p);

	BN_clear(&b);
	BN_clear(&B);
	BN_clear(&A);
	BN_clear(&s);
	BN_clear(&p);
	BN_clear(&g);
}

unsigned int dhke_session_send(unsigned char *crypted_msg, unsigned char *iv, unsigned char *plain_msg, unsigned int plain_msg_len, unsigned char *sess_key)
{
	// generate random iv
	aes_random_key(iv, 16);

	// perform encryption
	return aes_cbc_encrypt(128, crypted_msg, plain_msg, plain_msg_len, sess_key, iv);
}

unsigned int dhke_session_recv(unsigned char *plain_msg, unsigned char *crypt_msg, unsigned int crypt_msg_len, unsigned char *sess_key, unsigned char *iv)
{
	// perform decryption
	return aes_cbc_decrypt(128, plain_msg, crypt_msg, crypt_msg_len, sess_key, iv);
}

/**
 * When both targets use s = 0 as session key
 * this func decryots their msgs.
 *
 * s = 0 occurs, if:
 *     A = B = p (fixed key MITM)
 *     g = 0     (malicious group MITM)
 *     g = p     (malicious group MITM)
 **/
unsigned int dhke_attack_zero_session_key(unsigned char *plain, unsigned char *cmsg, unsigned int cmsg_len, unsigned char *iv)
{
	unsigned char obuf[20];

	// derive session key for s=0
	SHA1("", 0, obuf);

	// perform decryption
	return aes_cbc_decrypt(128, plain, cmsg, cmsg_len, obuf, iv);
}

/**
 * If g = p-1, use this function to decrypt
 * msgs with the derived session key.
 * s = p - 1, if A = B = p-1
 * s = 1, else
 **/
unsigned int dhke_attack_p_1_session_key(unsigned char *plain, unsigned char *cmsg, unsigned int cmsg_len, unsigned char *pubkey_A, unsigned char *pubkey_B, unsigned char *iv)
{
	unsigned char obuf[20];
	unsigned char sk[1024];
	short one_flag = 1;

	// check whether s = p - 1 or s = 1
	if(!strcmp(pubkey_A, pubkey_B)) {
		if(strlen(pubkey_A) > 2)
			one_flag = 0;
	}

	// s = 1
	if(one_flag) {
		// derive session key
		SHA1("01", 2, obuf);
	} else {
		// derive session key
		SHA1(pubkey_A, strlen(pubkey_A), obuf);
	}

	return aes_cbc_decrypt(128, plain, cmsg, cmsg_len, obuf, iv);
}

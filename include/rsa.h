/*
 * rsa.h
 *
 *  Created on: 25.10.2014
 *      Author: rc0r
 */

#ifndef INCLUDE_RSA_H_
#define INCLUDE_RSA_H_

#include <openssl/bn.h>
#include <openssl/rand.h>

/** RSA functions and stuff **/

static const char *BN_e_str = "3";

struct rsa_key {
	BIGNUM *e;
	BIGNUM *n;
};

typedef struct rsa_key rsa_key_t;

// generate RSA public and private keys
void rsa_generate_keypair(rsa_key_t *o_pubkey, rsa_key_t *o_privkey, unsigned long bits);

// perform core bignum encryption
void rsa_bn_encrypt(BIGNUM *o_crypt, BIGNUM *i_plain, rsa_key_t *i_pubkey);

// perform data encryption
unsigned int rsa_encrypt(unsigned char **o_crypt, unsigned char *i_plain, unsigned int i_plain_len, rsa_key_t *i_pubkey);

// perform core bignum decryption
void rsa_bn_decrypt(BIGNUM *o_plain, BIGNUM *i_crypt, rsa_key_t *i_privkey);

// perform data decryption
unsigned int rsa_decrypt(unsigned char **o_plain, unsigned char *i_crypt, unsigned int i_crypt_len, rsa_key_t *i_privkey);

/** Helper functions and stuff **/
struct egcd_result {
	BIGNUM *a;
	BIGNUM *u;
	BIGNUM *v;
};

typedef struct egcd_result egcd_result_t;

// calculate extended greatest common div. (euclidean algo.)
void egcd(egcd_result_t *o_result, BIGNUM *i_a, BIGNUM *i_b);
// calculate multiplicative inverse (invmod)
int inv_mod(BIGNUM *o_result, BIGNUM *i_a, BIGNUM *i_b);
// calculate Chinese remainder theorem
int crt(BIGNUM *o_result, BIGNUM *o_result_nonmod, BIGNUM **i_n, BIGNUM **i_a, unsigned int i_len);

#endif /* INCLUDE_RSA_H_ */

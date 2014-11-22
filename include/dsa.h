/*
 * dsa.h
 *
 * Created on: 07.11.2014
 * Author:     rc0r
 */

#ifndef INCLUDE_DSA_H_
#define INCLUDE_DSA_H_

#include "hash.h"
#include "ring.h"

/** DSA parameters **/
static const char *dsa_p = //"11b";
"800000000000000089e1855218a0e7dac38136ffafa72eda7\
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
1a584471bb1";

static const char *dsa_q = "f4f47f05794b256174bba6e9b396a7707e563c5b"; // "2f";

static const char *dsa_g = //"3c";
"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
9fc95302291";

struct dsa_key {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *xy;	// private/public key
};

typedef struct dsa_key dsa_key_t;

struct dsa_signature {
	BIGNUM *r;
	BIGNUM *s;
};

typedef struct dsa_signature dsa_signature_t;

/** DSA function prototypes **/
// allocate memory for all the bignums in a dsa_key_t struct
dsa_key_t *dsa_key_new(void);
// free memory of a dsa_key_t struct
void dsa_key_free(dsa_key_t *key);
// allocate memory for all the bignums in a dsa_signature_t struct
dsa_signature_t *dsa_signature_new(void);
// free memory of a dsa_signature_t struct
void dsa_signature_free(dsa_signature_t *key);

// generate DSA key pair from hard coded params
void dsa_generate_keypair(dsa_key_t *o_pubkey, dsa_key_t *o_privkey, unsigned long bits);
// DSA-SHA1 sign a message
void dsa_sha1_sign(dsa_signature_t *o_signature, unsigned char *i_msg, unsigned int i_msg_len, dsa_key_t *i_privkey);
// DSA-SHA1 sign a message using a fixed DSA session key k
void dsa_sha1_sign_fixed_k(dsa_signature_t *o_signature, unsigned char *i_msg, unsigned int i_msg_len, BIGNUM *i_k, dsa_key_t *i_privkey);
// verfiy DSA-SHA1 signed message
int dsa_sha1_sign_verify(unsigned char *i_msg, unsigned int i_msg_len, dsa_signature_t *i_signature, dsa_key_t *i_pubkey);
// calculate DSA private key from DSA subkey k range
int dsa_calc_private_key_from_k_range(dsa_key_t *o_privkey, dsa_signature_t *i_signature, unsigned long int i_range, unsigned char *i_msg, unsigned int i_msg_len, dsa_key_t *i_pubkey);
// calculate DSA private key from known DSA subkey k
int dsa_calc_private_key_from_k(dsa_key_t *o_privkey, dsa_signature_t *i_signature, BIGNUM *i_k, unsigned char *i_msg, unsigned int i_msg_len, dsa_key_t *i_pubkey);
// calculate DSA subkey k and private key from two messages that were signed using the same subkey k (nonce, session key)
int dsa_calc_private_key_from_reused_k(dsa_key_t *o_privkey, BIGNUM *o_k, dsa_signature_t *i_a, dsa_signature_t *i_b, unsigned char *i_msg_a, unsigned int i_msg_a_len, unsigned char *i_msg_b, unsigned int i_msg_b_len, dsa_key_t *i_pubkey);
// checks if two DSA signatures were generated using the same nonce
int dsa_sign_nonce_cmp(dsa_signature_t *i_a, dsa_signature_t *i_b);

/** test funcs **/

#endif /* INCLUDE_DSA_H_ */

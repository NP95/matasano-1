/*
 * dsa.c
 *
 * Created on: 07.11.2014
 * Author:     rc0r
 */

#include "../include/dsa.h"

/*
 * Allocates memory for all the BIGNUMs
 * that form a dsa_key_t struct.
 *
 * @return
 * 		Pointer to properly allocated dsa_key_t struct.
 */
dsa_key_t *dsa_key_new(void)
{
	dsa_key_t *key = malloc(sizeof(dsa_key_t));

	key->g = BN_new();
	key->p = BN_new();
	key->q = BN_new();
	key->xy = BN_new();

	return key;
}

/*
 * Free the memory that was previously allocated
 * for a dsa_key_t struct.
 *
 * @return
 * 		void.
 * @param key
 * 		Pointer to dsa_key_t struct.
 */
void dsa_key_free(dsa_key_t *key)
{
	BN_free(key->g);
	BN_free(key->p);
	BN_free(key->q);
	BN_free(key->xy);

	//free(key);
}

/*
 * Allocates memory for all the BIGNUMs
 * that form a dsa_signature_t struct.
 *
 * @return
 * 		Pointer to properly allocated dsa_signature_t struct.
 */
dsa_signature_t *dsa_signature_new(void)
{
	dsa_signature_t *signature = malloc(sizeof(dsa_signature_t));

	signature->r = BN_new();
	signature->s = BN_new();

	return signature;
}

/*
 * Free the memory that was previously allocated
 * for a dsa_signature_t struct.
 *
 * @return
 * 		void.
 * @param signature
 * 		Pointer to dsa_signature_t struct.
 */
void dsa_signature_free(dsa_signature_t *signature)
{
	BN_free(signature->r);
	BN_free(signature->s);

	//free(signature);
}

/*
 * Generate a DSA key pair.
 *
 * @return
 * 		void.
 * @param o_pubkey
 * 		Pointer to DSA public key.
 * @param o_privkey
 * 		Pointer to DSA private key.
 * @param i_bits
 * 		Number of bits for the private key. (Note: Value of
 * 		private key x will *always* be less than parameter q!)
 */
void dsa_generate_keypair(dsa_key_t *o_pubkey, dsa_key_t *o_privkey, unsigned long i_bits)
{
	BN_CTX *ctx = BN_CTX_new();

	// set g, p, q
	BN_hex2bn(&o_pubkey->g, dsa_g);
	BN_hex2bn(&o_pubkey->p, dsa_p);
	BN_hex2bn(&o_pubkey->q, dsa_q);
	BN_hex2bn(&o_privkey->g, dsa_g);
	BN_hex2bn(&o_privkey->p, dsa_p);
	BN_hex2bn(&o_privkey->q, dsa_q);

	// generate prime x
	unsigned int q_bits = strlen(dsa_q)*4;
	unsigned int x_bits = (i_bits <= q_bits) ? i_bits : q_bits;

	do {
		BN_generate_prime_ex(o_privkey->xy, x_bits, 1, NULL, NULL, NULL);
	} while(BN_cmp(o_privkey->xy, o_privkey->q)>=0); // a >= b?

	BN_mod_exp(o_pubkey->xy, o_pubkey->g, o_privkey->xy, o_pubkey->p, ctx);

	BN_CTX_free(ctx);
}

/*
 *  DSA sign a message using the SHA1 hash function.
 *
 *  @return
 *  	Void.
 *  @param o_signature
 *  	Pointer to dsa_signature_t struct holding the generated signature.
 *  @param i_msg
 *  	Input message that will be signed.
 *  @param i_msg_len
 *  	Length in bytes of input message.
 *  @param i_privkey
 *  	DSA private key that will be used for the signing operation.
 */
void dsa_sha1_sign(dsa_signature_t *o_signature, unsigned char *i_msg, unsigned int i_msg_len, dsa_key_t *i_privkey)
{
	BIGNUM *k = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *C1 = BN_new();

	BN_one(C1);
	BN_sub(T0, i_privkey->q, C1);

	// generate k, k^-1
	// #TODO: apropriate seed needed a-priori!
	BN_rand_range(k, T0);
//	unsigned char *kstr = "f";
//	BN_hex2bn(&k, kstr);

	dsa_sha1_sign_fixed_k(o_signature, i_msg, i_msg_len, k, i_privkey);

	BN_free(C1);
	BN_free(T0);
	BN_free(k);
}

/*
 *  DSA sign a message using the SHA1 hash function
 *  using a fixed DSA session key k.
 *
 *  @return
 *  	Void.
 *  @param o_signature
 *  	Pointer to dsa_signature_t struct holding the generated signature.
 *  @param i_msg
 *  	Input message that will be signed.
 *  @param i_msg_len
 *  	Length in bytes of input message.
 *  @param i_k
 *  	Pointer to BIGNUM holding the DSA session key to be used for signing.
 *  @param i_privkey
 *  	DSA private key that will be used for the signing operation.
 */
void dsa_sha1_sign_fixed_k(dsa_signature_t *o_signature, unsigned char *i_msg, unsigned int i_msg_len, BIGNUM *i_k, dsa_key_t *i_privkey)
{
	BIGNUM *k_inv = BN_new();
	BIGNUM *H = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

//	inv_mod(k_inv, i_privkey->q, k);
	BN_mod_inverse(k_inv, i_k, i_privkey->q, ctx);

	// r = (g^k mod p) mod q
	BN_mod_exp(T0, i_privkey->g, i_k, i_privkey->p, ctx);
	BN_mod(o_signature->r, T0, i_privkey->q, ctx);

	// generate H(m) (= SHA1(m))
	unsigned char hash_hex[SHA_DIGEST_LENGTH*2+1];
	hash_sha1(hash_hex, i_msg, i_msg_len);
//	unsigned char *hash_hex = "29";
	BN_hex2bn(&H, hash_hex);

	// s = (k^-1 (H + xr)) mod q
	BN_mod_mul(T0, i_privkey->xy, o_signature->r, i_privkey->q, ctx);
	BN_mod_add(T1, H, T0, i_privkey->q, ctx);
	BN_mod_mul(o_signature->s, k_inv, T1, i_privkey->q, ctx);

	BN_free(k_inv);
	BN_free(H);
	BN_free(T0);
	BN_free(T1);

	BN_CTX_free(ctx);
}

/*
 * Verifies the DSA (SHA-1) signature for a given message.
 *
 * @return
 * 		Returns 1 if the signature was successfully
 * 		verified, 0 if the signature could not be verified
 * 		and -1 on error.
 * @param i_msg
 * 		Message to verify.
 * @param i_msg_len
 * 		Length in bytes of the message.
 * @param i_signature
 * 		Pointer to dsa_signature_t struct holding the DSA-SHA1 signature of
 * 		the message.
 * @param i_pubkey
 * 		DSA public key to use for verification.
 */
int dsa_sha1_sign_verify(unsigned char *i_msg, unsigned int i_msg_len, dsa_signature_t *i_signature, dsa_key_t *i_pubkey)
{
	int failed = 0;

	if((BN_cmp(i_signature->r, i_pubkey->q)>=0) || BN_is_zero(i_signature->r)) {
		failed = 1;
	} else {
		if((BN_cmp(i_signature->s, i_pubkey->q)>=0) || BN_is_zero(i_signature->s)) {
			failed = 1;
		}
	}

	BIGNUM *H = BN_new();
	BIGNUM *s_inv = BN_new();
	BIGNUM *u1 = BN_new();
	BIGNUM *u2 = BN_new();
	BIGNUM *v = BN_new();
	BIGNUM *w = BN_new();

	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();
	BIGNUM *T2 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// generate H(m) (= SHA1(m))
	unsigned char hash_hex[SHA_DIGEST_LENGTH*2+1];
	hash_sha1(hash_hex, i_msg, i_msg_len);
//	unsigned char *hash_hex = "29";
	BN_hex2bn(&H, hash_hex);

	// w = s^-1 mod q
//	inv_mod(w, i_pubkey->q, i_signature->s);
	BN_mod_inverse(w, i_signature->s, i_pubkey->q, ctx);

	// u1 = H*w mod q
	BN_mod_mul(u1, H, w, i_pubkey->q, ctx);

	// u2 = r*w mod q
	BN_mod_mul(u2, i_signature->r, w, i_pubkey->q, ctx);

	// v = ((g^u1 * y^u2) mod p) mod q
	BN_mod_exp(T0, i_pubkey->g, u1, i_pubkey->p, ctx);
	BN_mod_exp(T1, i_pubkey->xy, u2, i_pubkey->p, ctx);
	BN_mod_mul(T2, T0, T1, i_pubkey->p, ctx);
	BN_mod(v, T2, i_pubkey->q, ctx);

	if(BN_cmp(v, i_signature->r)!=0) {
		failed = 1;
	}

	BN_free(H);
	BN_free(s_inv);
	BN_free(u1);
	BN_free(u2);
	BN_free(v);
	BN_free(w);
	BN_free(T0);
	BN_free(T1);
	BN_free(T2);

	BN_CTX_free(ctx);

	if(failed) {
		return 0;
	} else {
		return 1;
	}
}

/*
 * Calculates a DSA private key from a DSA subkey k,
 * that is known to be in a specific range.
 *
 * @return
 * 		1 on success, 0 if private could not be calculated.
 * @param o_privkey
 * 		Pointer to struct dsa_key_t that will hold the calculated private key.
 * @param i_signature
 * 		Struct dsa_signature_t holding the DSA signature for a message.
 * @param i_range
 * 		Keysearch will be performed in range [0, i_range].
 * @param i_msg
 * 		String holding the corresponding message.
 * @param i_msg_len
 * 		Length in bytes of the message.
 * @param i_pubkey
 * 		DSA public key.
 */
int dsa_calc_private_key_from_k(dsa_key_t *o_privkey, dsa_signature_t *i_signature, unsigned long int i_range, unsigned char *i_msg, unsigned int i_msg_len, dsa_key_t *i_pubkey)
{
	BIGNUM *H = BN_new();
	BIGNUM *k = BN_new();
	BIGNUM *r_inv = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// generate H(m) (= SHA1(m))
	unsigned char hash_hex[SHA_DIGEST_LENGTH*2+1];
	hash_sha1(hash_hex, i_msg, i_msg_len);
//	unsigned char *hash_hex = "29";
	BN_hex2bn(&H, hash_hex);

//	BN_print_fp(stdout, H);
//	printf("\n");

	// calc r^-1
//	inv_mod(r_inv, i_pubkey->q, i_signature->r);
	BN_mod_inverse(r_inv, i_signature->r, i_pubkey->q, ctx);

	unsigned long int i, j;
	unsigned int success = 0;
	dsa_signature_t dsa_sign;

	dsa_sign.r = BN_new();
	dsa_sign.s = BN_new();

	BN_copy(o_privkey->g, i_pubkey->g);
	BN_copy(o_privkey->p, i_pubkey->p);
	BN_copy(o_privkey->q, i_pubkey->q);

	for(i=1; i<=i_range; i++) {
		BN_set_word(k, i);

		BN_mod_mul(T0, i_signature->s, k, i_pubkey->q, ctx);
		BN_mod_sub(T1, T0, H, i_pubkey->q, ctx);
		BN_mod_mul(o_privkey->xy, T1, r_inv, i_pubkey->q, ctx);

		/*unsigned char *key_str = BN_bn2hex(o_privkey->xy);
		// convert to lower case
		for(j=0; j<strlen(key_str); j++) {
			key_str[j] = tolower(key_str[j]);
		}
		unsigned char sha1_key[SHA_DIGEST_LENGTH*2+1];
		hash_sha1(sha1_key, key_str, strlen(key_str));
		OPENSSL_free(key_str);

		if(!strcmp(sha1_key, "0954edd5e0afe5542a4adf012611a91912a3ec16")) {
			success = 1;
			break;
		}*/

		dsa_sha1_sign_fixed_k(&dsa_sign, i_msg, i_msg_len, k, o_privkey);
		if(!BN_cmp(dsa_sign.r, i_signature->r) && !BN_cmp(dsa_sign.s, i_signature->s)) {
			success = 1;
			break;
		}
		// doesn't work (why?):
		/*if(dsa_sha1_sign_verify(i_msg, i_msg_len, &dsa_sign, i_pubkey)) {
			success = 1;
			break;
		}*/
	}

	dsa_signature_free(&dsa_sign);

	BN_CTX_free(ctx);

	BN_free(T0);
	BN_free(T1);
	BN_free(r_inv);
	BN_free(k);
	BN_free(H);

	if(success) {
		return 1;
	} else {
		return 0;
	}
}

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

	free(key);
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

	free(signature);
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

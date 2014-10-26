/*
 * rsa.c
 *
 *  Created on: 25.10.2014
 *      Author: rc0r
 */

#include "../include/hex_coder.h"
#include "../include/rsa.h"

void rsa_generate_keypair(rsa_key_t *o_pubkey, rsa_key_t *o_privkey, unsigned long i_bits)
{
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *t = BN_new();

	BIGNUM *C1 = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// set e = BN_e_str (=3)
	BN_hex2bn(&o_pubkey->e, BN_e_str);

	// generate primes p, q (p != q)
	BN_generate_prime_ex(p, i_bits, 1, NULL, NULL, NULL);
	do {
		BN_generate_prime_ex(q, i_bits, 1, NULL, NULL, NULL);
	} while(!BN_cmp(p, q));

	// n = p*q
	BN_mul(o_pubkey->n, p, q, ctx);
	BN_copy(o_privkey->n, o_pubkey->n);

	// t = (p-1)*(q-1) = 1 + p*q - (p + q)
	BN_one(C1);
	BN_mod_mul(T0, p, q, o_pubkey->n, ctx);
	BN_mod_add(T1, C1, T0, o_pubkey->n, ctx);
	BN_mod_add(T0, p, q, o_pubkey->n, ctx);
	BN_mod_sub(t, T1, T0, o_pubkey->n, ctx);

	// e' = d = invmod(e, t)
	// ok we're cheating here. using our own buggy invmod
	// func seems not to be a good idea. needs improving
	// first.
	BN_mod_inverse(o_privkey->e, o_pubkey->e, t, ctx);

	BN_free(p);
	BN_free(q);
	BN_free(t);

	BN_free(T0);
	BN_free(T1);

	BN_CTX_free(ctx);
}

void rsa_bn_encrypt(BIGNUM *o_crypted, BIGNUM *i_plain, rsa_key_t *i_pubkey)
{
	BN_CTX *ctx = BN_CTX_new();
	// c = m^e % n
	BN_mod_exp(o_crypted, i_plain, i_pubkey->e, i_pubkey->n, ctx);
	BN_CTX_free(ctx);
}

void rsa_bn_decrypt(BIGNUM *o_plain, BIGNUM *i_crypted, rsa_key_t *i_privkey)
{
	BN_CTX *ctx = BN_CTX_new();
	// m = c^d % n
	BN_mod_exp(o_plain, i_crypted, i_privkey->e, i_privkey->n, ctx);
	BN_CTX_free(ctx);
}

unsigned int rsa_encrypt(unsigned char **o_crypt, unsigned char *i_plain, unsigned int i_plain_len, rsa_key_t *i_pubkey)
{
	unsigned char *plain_hex = NULL;
	unsigned char *crypt_hex = NULL;
	unsigned int crypt_len = 0;
	hex_encode(&plain_hex, i_plain, i_plain_len);

	BIGNUM *plain = BN_new();
	BIGNUM *crypt = BN_new();

	BN_hex2bn(&plain, plain_hex);

	rsa_bn_encrypt(crypt, plain, i_pubkey);

	crypt_hex = BN_bn2hex(crypt);

	crypt_len = hex_decode(o_crypt, crypt_hex, strlen(crypt_hex));

	BN_free(plain);
	BN_free(crypt);

	OPENSSL_free(crypt_hex);
	free(plain_hex);

	return crypt_len;
}

unsigned int rsa_decrypt(unsigned char **o_plain, unsigned char *i_crypt, unsigned int i_crypt_len, rsa_key_t *i_privkey)
{
	unsigned char *plain_hex = NULL;
	unsigned char *crypt_hex = NULL;
	unsigned int plain_len = 0;
	hex_encode(&crypt_hex, i_crypt, i_crypt_len);

	BIGNUM *plain = BN_new();
	BIGNUM *crypt = BN_new();

	BN_hex2bn(&crypt, crypt_hex);

	rsa_bn_decrypt(plain, crypt, i_privkey);

	plain_hex = BN_bn2hex(plain);
//	plain_len = 2*BN_num_bytes(plain);
	plain_len = strlen(plain_hex);

	plain_len = hex_decode(o_plain, plain_hex, plain_len);

	BN_free(plain);
	BN_free(crypt);

	OPENSSL_free(plain_hex);
	free(crypt_hex);

	return plain_len;
}

/*** Helper functions ***/
/*
 * Calculates extended euclidean algorithm of two numbers.
 * @NOTE: Might give wrong results for negative numbers a, b.
 *
 * #TODO:
 * Make this work correctly for negative numbers (see:
 * http://rosettacode.org/wiki/Modular_inverse)!
 */
void egcd(egcd_result_t *o_result, BIGNUM *i_a, BIGNUM *i_b)
{
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();

	BIGNUM *q = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *t = BN_new();

	BIGNUM *C0 = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	BN_zero(s);
	BN_one(t);
	BN_one(o_result->u);
	BN_zero(o_result->v);
	BN_zero(C0);

	BN_copy(a, i_a);
	BN_copy(b, i_b);

	unsigned int i = 0;

	while(BN_cmp(b, C0) > 0) {
		BN_div(q, r, a, b, ctx);

		// a, b = b, a-q*b
		BN_mul(T0, q, b, ctx);
		BN_sub(T1, a, T0);
		BN_copy(a, b);
		BN_copy(b, T1);

		// u, s = s, u-q*s
		BN_mul(T0, q, s, ctx);
		BN_sub(T1, o_result->u, T0);
		BN_copy(o_result->u, s);
		BN_copy(s, T1);

		// v, t = t, v-q*t
		BN_mul(T0, q, t, ctx);
		BN_sub(T1, o_result->v, T0);
		BN_copy(o_result->v, t);
		BN_copy(t, T1);
	}

	BN_copy(o_result->a, a);

	BN_free(a);
	BN_free(b);
	BN_free(q);
	BN_free(r);
	BN_free(s);
	BN_free(t);
	BN_free(C0);
	BN_free(T0);
	BN_free(T1);
	BN_CTX_free(ctx);
}

/*
 * Calculates modular multiplicative inverse using the extended
 * euclidean algorthim:
 * Returns 'result' where (op1*result) % op2 == 1.
 *
 * @NOTE: Might give wrong results for negative parameters op1, op2
 * since we're using egcd() here!
 *
 * #TODO:
 * Make this work correctly for negative numbers (see:
 * http://rosettacode.org/wiki/Modular_inverse)!
 */
int inv_mod(BIGNUM *result, BIGNUM *op1, BIGNUM *op2)
{
	egcd_result_t res;

	res.a = BN_new();
	res.u = BN_new();
	res.v = BN_new();

	egcd(&res, op1, op2);

	if(!BN_is_one(res.a)) {
		return -1;
	}

	if(BN_is_negative(res.v)) {
		BN_add(result, res.v, op1);
	}
	else {
		BN_copy(result, res.v);
	}

	BN_free(res.a);
	BN_free(res.u);
	BN_free(res.v);

	return 0;
}

/*
 * Calculates Chinese remainder theorem.
 *
 * @NOTE: Might give wrong results for negative parameters op1, op2
 * since we're using egcd() here!
 *
 * Source: http://rosettacode.org/wiki/Chinese_remainder_theorem
 */
int crt(BIGNUM *o_result, BIGNUM *o_result_nonmod, BIGNUM **i_n, BIGNUM **i_a, unsigned int i_len)
{
	BIGNUM *p = BN_new();
	BIGNUM *prod = BN_new();
	BIGNUM *sum = BN_new();
	BIGNUM *rem = BN_new();

	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();
	BIGNUM *T2 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	unsigned int i, failed = 0;

	BN_one(prod);
	BN_zero(sum);

	for(i=0; i<i_len; i++) {
		BN_mul(T0, prod, i_n[i], ctx);
		BN_copy(prod, T0);
	}

	for(i=0; i<i_len; i++) {
		BN_div(p, rem, prod, i_n[i], ctx);

		if(!inv_mod(T0, i_n[i], p)) {
			BN_mul(T1, T0, p, ctx);
			BN_mul(T2, T1, i_a[i], ctx);
			BN_add(T0, sum, T2);
			BN_copy(sum, T0);
		}
		else {
			failed = 1;
			break;
		}
	}

	BN_copy(o_result_nonmod, sum);
	BN_mod(o_result, sum, prod, ctx);

	BN_free(p);
	BN_free(prod);
	BN_free(sum);
	BN_free(rem);

	BN_free(T0);
	BN_free(T1);
	BN_free(T2);

	BN_CTX_free(ctx);

	if(failed) {
		return -1;
	} else {
		return 0;
	}
}

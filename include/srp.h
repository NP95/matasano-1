#ifndef __SRP_H
#define __SRP_H

#include <openssl/sha.h>

#include "dh.h"

/** SRP helper funcs **/
void srp_generate_salted_password_hash(BIGNUM *o_intHash, unsigned char *o_strHash, const unsigned char *i_salt, const unsigned char *i_password);
void srp_generate_pubkey_hash(BIGNUM *o_intHash, BIGNUM *i_A, BIGNUM *i_B);
unsigned int srp_generate_session_hmac(unsigned char *o_hmac, unsigned char *i_session_key, unsigned char i_salt);

/** SRP Protocol simulation funcs **/
void srp_server_init(unsigned char *o_salt, BIGNUM *o_v, BIGNUM *o_b, BIGNUM *o_B, unsigned char *i_password, BIGNUM *i_g, BIGNUM *i_N);
void srp_server_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, BIGNUM *i_A, BIGNUM *i_b, BIGNUM *i_B, BIGNUM *i_v, BIGNUM *i_N);

void srp_client_init(BIGNUM *o_a, BIGNUM *o_A, BIGNUM *i_g, BIGNUM *i_N);
void srp_client_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, unsigned char *i_salt, unsigned char *i_password, BIGNUM *i_a, BIGNUM *i_A, BIGNUM *i_B, BIGNUM *i_g, BIGNUM *i_N);

#endif // __SRP_H


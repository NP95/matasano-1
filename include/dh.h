#ifndef __DH_H
#define __DH_H

#include <math.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// smallnum constants
static const unsigned int p_smallint = 37;
static const unsigned int g_smallint = 5;

// smallnum funcs
void dh_generate_keypair_smallint(unsigned long *priv_key, unsigned long *pub_key);
unsigned long dh_generate_session_key_smallint(unsigned long priv_key, unsigned long pub_key);

/** REAL STUFF FOLLOWS **/

// bignum constants
static const char *BN_p_str =
"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";
static const char *BN_g_str = "2";

/** DH BASE FUNCS **/
void dh_init(BIGNUM *p, BIGNUM *g);
void dh_clear(BIGNUM *p, BIGNUM *g);

void dh_generate_keypair(BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *g, BIGNUM *p);
void dh_generate_session_key(unsigned char *c_session_key, BIGNUM *session_key, BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *p);

/** DHKE SIMULATION FUNCS **/
void dhke_initiate(unsigned char *c_p, unsigned char *c_g, unsigned char *c_pub_key, BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *p, BIGNUM *g);
void dhke_initiate_finalize(unsigned char *sess_key, unsigned char *pub_key_reply, BIGNUM *priv_key, BIGNUM *p);
void dhke_initiate_reply(unsigned char *pub_key_reply, unsigned char *c_p, unsigned char *c_g, unsigned char *pub_key_init, unsigned char *sess_key);
unsigned int dhke_session_send(unsigned char *crypted_msg, unsigned char *iv, unsigned char *plain_msg, unsigned int plain_msg_len, unsigned char *sess_key);
unsigned int dhke_session_recv(unsigned char *plain_msg, unsigned char *crypt_msg, unsigned int crypt_msg_len, unsigned char *sess_key, unsigned char *iv);

#endif // __DH_H

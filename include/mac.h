#ifndef __MAC_H
#define __MAC_H

#include <openssl/hmac.h>

#include "md4.h"
#include "sha1.h"

// MD4
unsigned int md4_secret_prefix_mac(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);
unsigned int md4_secret_prefix_mac_forge(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *orig_hash);
unsigned int md4_secret_prefix_mac_auth(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);
unsigned int md4_generate_padding(unsigned char *padding, unsigned long message_len);

// SHA-1
unsigned int sha1_secret_prefix_mac(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);
unsigned int sha1_generate_padding(unsigned char *padding, unsigned long message_len);
unsigned int sha1_secret_prefix_mac_auth(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);

// SHA-1 attacks
unsigned int sha1_secret_prefix_mac_forge(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned int *orig_hash);

// SHA-256
unsigned int sha256_secret_prefix_mac(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);
#endif // __MAC_H


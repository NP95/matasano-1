#ifndef __MAC_H
#define __MAC_H

#include "sha1.h"

unsigned int sha1_secret_prefix_mac(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);
unsigned int sha1_secret_prefix_mac_auth(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len);

#endif // __MAC_H


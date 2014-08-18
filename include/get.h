#ifndef __GET_H
#define __GET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct key_value {
	unsigned char *key;
	unsigned char *value;
};

typedef struct key_value kv_t;

unsigned int decode_from_get(kv_t *kv_pairs, unsigned char *get_request);
unsigned int encode_to_get(unsigned char *get_request, kv_t *kv_pairs, unsigned int kv_entries);
unsigned int profile_for(unsigned char *encoded_profile, kv_t *profile, unsigned char *mail);

#endif // __GET_H

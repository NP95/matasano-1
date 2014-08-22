#include "../include/histogram.h"
#include "../include/xor.h"
#include <stdio.h>

void fixed_xor(unsigned char **out, unsigned char *in1, unsigned char *in2, unsigned int in_size)
{
	unsigned int i;

	(*out) = malloc((in_size)*sizeof(unsigned char));
	memset((*out), 0, (in_size)*sizeof(unsigned char));

	for(i=0; i<in_size; i++) {
		(*out)[i] = in1[i] ^ in2[i];
	}

	return;
}

unsigned int xor_key(unsigned char **out, unsigned char *in, unsigned int in_size, unsigned char *key, unsigned int key_size)
{
	unsigned int i;

	(*out) = malloc((in_size+1)*sizeof(unsigned char));
	memset((*out), 0, (in_size+1)*sizeof(unsigned char));

	for(i=0; i<in_size; i++) {
		(*out)[i] = in[i] ^ key[i % key_size];
	}

	return i;
}

int attack_single_byte_xor(unsigned char **out, unsigned char **key, unsigned char *cipher, unsigned int cipher_size)
{
	unsigned int i;
	unsigned char k;
	unsigned char *clear_text;
	unsigned char *tmp_key;
	max_hist_t e;

	(*key) = malloc((cipher_size+1)*sizeof(unsigned char));
	memset((*key), 0, (cipher_size+1)*sizeof(unsigned char));
	
	(*out) = malloc((cipher_size+1)*sizeof(unsigned char));
	memset((*out), 0, (cipher_size+1)*sizeof(unsigned char));


	e = histogram(cipher, cipher_size, 0);

	for(i=0; i<13; i++) {
// 		printf("%02x x %d\n", e.byte[i], e.num[i]);

		tmp_key = malloc((cipher_size+1)*sizeof(unsigned char));
		memset(tmp_key, 0, (cipher_size+1)*sizeof(unsigned char));

		// p ^ k = c, c ^ k = p => c ^ p = k
		// calculate key
		k = e.byte[0] ^ hist_most_common[i];
		memset(tmp_key, k, cipher_size);

// 		printf("key[str] = '%s'\n", (*key));

		fixed_xor(&clear_text, cipher, tmp_key, cipher_size);

// 		printf("clear[str] = '%s'\n", (*out));

		if(is_cleartext(clear_text, cipher_size)==0) {
			memcpy((*key), tmp_key, cipher_size*sizeof(unsigned char));
			memcpy((*out), clear_text, cipher_size*sizeof(unsigned char));
			free(clear_text);
			free(tmp_key);
			return 0;
		}
		
		free(clear_text);
		free(tmp_key);
	}

	return -1;
}

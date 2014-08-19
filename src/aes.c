#include "../include/aes.h"

unsigned int aes_ecb_encrypt(unsigned int block_len_bits, unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key)
{
	unsigned int i;
	AES_KEY enc_key;
	AES_set_encrypt_key(key, block_len_bits, &enc_key);

	for(i=0; i<plaintext_len; i+=(block_len_bits/8)) {
		AES_ecb_encrypt(plaintext+i, ciphertext+i, &enc_key, AES_ENCRYPT);
	}

	return i;
}

unsigned int aes_ecb_decrypt(unsigned int block_len_bits, unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key)
{
	unsigned int i;
	AES_KEY dec_key;
	AES_set_decrypt_key(key, block_len_bits, &dec_key);

	for(i=0; i<ciphertext_len; i+=(block_len_bits/8)) {
		AES_ecb_encrypt(ciphertext+i, plaintext+i, &dec_key, AES_DECRYPT);
	}

	return i;
}

unsigned int aes_cbc_encrypt(unsigned int block_len_bits, unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, unsigned char *iv)
{
	unsigned int i, j;
	unsigned int block_size = block_len_bits / 8; // block len in bytes
	unsigned int num_blocks = plaintext_len / block_size;
	unsigned char pn[block_size];
	unsigned char cn[block_size];
	unsigned char *qn;
	unsigned int bytes = 0;

	// initialize c0 = IV
	for(i=0; i<(block_size); i++) {
		cn[i] = iv[i];
	}

	for(i=0; i<num_blocks; i++) {
		for(j=0; j<block_size; j++) {
			// initialize plaintext block
			pn[j] = plaintext[j+i*block_size];
		}

		fixed_xor(&qn, pn, cn, block_size);
		bytes += aes_ecb_encrypt(block_len_bits, cn, qn, block_size, key);

		// write cn to output array
		for(j=0; j<block_size; j++) {
			ciphertext[j+i*block_size] = cn[j];
		}

		free(qn);
	}

	return bytes;
}

unsigned int aes_cbc_decrypt(unsigned int block_len_bits, unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	unsigned int i, j;
	unsigned int block_size = block_len_bits / 8; // block len in bytes
	unsigned int num_blocks = ciphertext_len / block_size;
	unsigned char *pn;
	unsigned char cn[block_size];
	unsigned char cn_1[block_size];
	unsigned char qn[block_size];
	unsigned int bytes = 0;

	// initialize c0 = IV
	for(i=0; i<(block_size); i++) {
		cn_1[i] = iv[i];
	}

	for(i=0; i<num_blocks; i++) {
		for(j=0; j<block_size; j++) {
			// initialize ciphertext block
			cn[j] = ciphertext[j+i*block_size];
		}

		bytes += aes_ecb_decrypt(block_len_bits, qn, cn, block_size, key);
		fixed_xor(&pn, qn, cn_1, block_size);

		// write cn to output array and update cn_1
		for(j=0; j<block_size; j++) {
			plaintext[j+i*block_size] = pn[j];
			cn_1[j] = cn[j];
		}

		free(pn);
	}

	return bytes;
}

unsigned int aes_ecb_partial_crack(unsigned char *plaintext, unsigned int *plaintext_length, unsigned int *key_length)
{
	unsigned char random_key[16];
	unsigned char ciphertext[1024];
	unsigned char *ciphertext_hex;
	unsigned int ciphertext_length;
	unsigned char *known_plaintext;
	unsigned int i, j, k;
	double hn;

	// initialize key length
	(*key_length) = 0;

	// initialize random encryption key
	aes_random_key(random_key, 16);

	// determine block size and check for ECB mode
	k = 1000;
	for(i=2; i<80; i++) {
		known_plaintext = malloc(i*sizeof(unsigned char));
		memset(known_plaintext, 'A', i*sizeof(unsigned char));
		ciphertext_length = aes_encryption_random(ciphertext, known_plaintext, i, random_key);
		hn = norm_hamming_distance(ciphertext, i, (unsigned int) ceil((double)i/2));
		k = is_ecb_mode(ciphertext, i, (unsigned int) ceil((double)i/2));

// 		hex_encode(&ciphertext_hex, ciphertext, ciphertext_length);
// 		printf("[%d] cipher = '%s'\n", i, ciphertext_hex);
// 		free(ciphertext_hex);

		free(known_plaintext);

		// key length found: stop
		if(hn == 0.0) {
			(*key_length) = ((unsigned int) ceil((double)i/2));
			ciphertext_length -= 2*(*key_length);
			printf("[s2c4] Is ECB Cipher? %s!\nECB Cipher Blocksize: %d\n", (k==0) ? "yes" : "no", (*key_length));
			break;
		}
	}

	// now on to the crckng!
	unsigned char plaintext_one_off[ciphertext_length];
	unsigned char cipher_one_off_save[1024];
	unsigned int cipher_one_off_save_length;
	unsigned char cipher_one_off[1024];
	unsigned int cipher_one_off_length;

	(*plaintext_length) = 0;

	for(i=0; i<ciphertext_length; i++) {
		memset(plaintext_one_off, 0, (ciphertext_length-i-1)*sizeof(unsigned char));
		for(j=ciphertext_length-i-1, k=0; j<ciphertext_length-1; j++, k++) {
			plaintext_one_off[j] = plaintext[k];
		}

		cipher_one_off_save_length = aes_encryption_random(cipher_one_off_save, plaintext_one_off, ciphertext_length-i-1, random_key);

		for(j=0; j<256; j++) {
			plaintext_one_off[ciphertext_length-1] = j;

			cipher_one_off_length = aes_encryption_random(cipher_one_off, plaintext_one_off, ciphertext_length, random_key);

			// compare to saved one-off cipher
			if(memcmp(cipher_one_off, cipher_one_off_save, ciphertext_length)==0) {
				plaintext[i] = plaintext_one_off[ciphertext_length-1];
				(*plaintext_length)++;
				break;
			}
		}
	}

	return (*plaintext_length);
}

unsigned int aes_ecb_detect_garbage_header(unsigned char *no_garbage_cipher, unsigned char *garbage_cipher, unsigned int garbage_cipher_len, unsigned int block_len)
{
	unsigned int num_blocks = garbage_cipher_len / block_len;
	unsigned char garb_blocks[num_blocks][block_len];
	unsigned int i, j, found_at=0;

	// initialize blocks
	for(i=0; i<num_blocks; i++) {
		for(j=0; j<block_len; j++) {
			garb_blocks[i][j] = garbage_cipher[i*block_len+j];
		}
		// check for two identical blocks
		if(i>0) {
			if(memcmp(garb_blocks[i-1], garb_blocks[i], block_len)==0) {
				found_at = (i+1)*block_len;
			}
		}
	}

	memcpy(no_garbage_cipher, garbage_cipher+found_at, (garbage_cipher_len-found_at)*sizeof(unsigned char));

	return (garbage_cipher_len-found_at);
}

unsigned int aes_ecb_partial_crack2(unsigned char *plaintext, unsigned int *plaintext_length, unsigned int *key_length)
{
	unsigned char random_key[16];

	unsigned int random_header_len = rand() % 64;
	unsigned char random_header[random_header_len];
	unsigned char ciphertext[1024];
	unsigned char no_garb_ciphertext[1024];
	unsigned char *ciphertext_hex;
	unsigned int garbage_ciphertext_length;
	unsigned int ciphertext_length;
	unsigned int nog_ciphertext_length;
	unsigned char known_plaintext[1024];
	unsigned int i, j, k;
	unsigned int prepad_size = 0;
	unsigned int garbage_len = 0;
	double hn;

	// initialize key length
	(*key_length) = 0;

	// initialize random encryption key
	// and random header
	aes_random_key(random_key, 16);
	(*key_length) = 16;
	aes_random_key(random_header, random_header_len);

	// perform garbage detection
	// detect random blocks, remove them, determine attacker
	// controlled + target cipher size
	memset(known_plaintext, 'A', 1024*sizeof(unsigned char));
	for(i=0; i<16; i++) {
		garbage_ciphertext_length = aes_encryption_random2(ciphertext, known_plaintext, i+2*16, random_header, random_header_len, random_key);
// 		hex_encode(&ciphertext_hex, ciphertext, ciphertext_length);
// 		printf("[s2c6] cipher = '%s'\n", ciphertext_hex);
// 		free(ciphertext_hex);
		ciphertext_length = aes_ecb_detect_garbage_header(no_garb_ciphertext, ciphertext, garbage_ciphertext_length, 16);
// 		hex_encode(&ciphertext_hex, no_garb_ciphertext, ciphertext_length);
// 		printf("[s2c6] no_garb_cipher = '%s'\n",ciphertext_hex);
// 		free(ciphertext_hex);
		if(garbage_ciphertext_length>ciphertext_length) {
			prepad_size = i;
			garbage_len = garbage_ciphertext_length-ciphertext_length-prepad_size-32;
			break;
		}
	}
	printf("[s2c6] cipher_len = %d, prepad_size = %d, random_header_len = %d\n", ciphertext_length, prepad_size, garbage_len);

	// now on to the crckng!
	unsigned char plaintext_one_off[ciphertext_length];

	unsigned int sendbuf_len = prepad_size+ciphertext_length;
	unsigned char sendbuf[sendbuf_len];


	unsigned char cipher_one_off_save[1024];
	unsigned int cipher_one_off_save_length;

	unsigned char nog_cipher_one_off_save[1024];
	unsigned int nog_cipher_one_off_save_length;

	unsigned char cipher_one_off[1024];
	unsigned int cipher_one_off_length;

	unsigned char nog_cipher_one_off[1024];
	unsigned int nog_cipher_one_off_length;

	(*plaintext_length) = 0;

	memset(sendbuf, 'B', sendbuf_len*sizeof(unsigned char));
	for(i=0; i<ciphertext_length; i++) {
		memset(plaintext_one_off, 'A', (ciphertext_length-i-1)*sizeof(unsigned char));
		for(j=ciphertext_length-i-1, k=0; j<ciphertext_length-1; j++, k++) {
			plaintext_one_off[j] = plaintext[k];
		}

		memcpy(sendbuf+prepad_size, plaintext_one_off, (ciphertext_length-1)*sizeof(unsigned char));
		cipher_one_off_save_length = aes_encryption_random2(cipher_one_off_save, sendbuf, sendbuf_len-i-1, random_header, random_header_len, random_key);

		for(j=0; j<256; j++) {
			memset(sendbuf, 'B', sendbuf_len*sizeof(unsigned char));
			plaintext_one_off[ciphertext_length-1] = j;

			memcpy(sendbuf+prepad_size, plaintext_one_off, ciphertext_length*sizeof(unsigned char));
			cipher_one_off_length = aes_encryption_random2(cipher_one_off, sendbuf, sendbuf_len, random_header, random_header_len, random_key);
// 			printf("[%d] saved_len = %d, cur_len = %d\n", j, nog_cipher_one_off_save_length, nog_cipher_one_off_length);

			// compare to saved one-off cipher
			if(memcmp(cipher_one_off+prepad_size+garbage_len, cipher_one_off_save+prepad_size+garbage_len, ciphertext_length)==0) {
				plaintext[i] = plaintext_one_off[ciphertext_length-1];
				(*plaintext_length)++;
				break;
			}
		}
	}

	return (*plaintext_length);
}

void aes_random_key(unsigned char *key, unsigned int key_size)
{
	unsigned int i;
// 	srand((unsigned int) time(NULL));

	for(i=0; i<key_size; i++) {
		key[i] = rand() % 256;
	}

	return;
}

unsigned int aes_encryption_oracle(unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len)
{
	unsigned char key[16];
	unsigned char iv[16];
	unsigned int header, trailer;
	unsigned int i;

	// chose random key & IV
	aes_random_key(key, 16);
	aes_random_key(iv, 16);

// 	srand((unsigned int) time(NULL));

	header = 5 + (rand() % 6);
	trailer = 5 + (rand() % 6);

	unsigned char plaintext_mod[header+plaintext_len+trailer];

	// set header
	for(i=0; i<header; i++) {
		plaintext_mod[i] = rand() % 256;
	}

	// set plaintext
	for(i=0; i<header; i++) {
		plaintext_mod[header+i] = plaintext[i];
	}

	// set trailer
	for(i=0; i<trailer; i++) {
		plaintext_mod[header+plaintext_len+i] = rand() % 256;
	}

	// perform PKCS#7 padding
	unsigned int plaintext_mod_padded_len = header + plaintext_len + trailer + (16 - ((header+plaintext_len+trailer) % 16));
	unsigned char plaintext_mod_padded[plaintext_mod_padded_len];

	plaintext_mod_padded_len = pkcs7_padding(plaintext_mod_padded, plaintext_mod, header+plaintext_len+trailer, 16);

	// roll the dice
	unsigned int dice = rand() % 2;

	// encrypt
	switch(dice) {
		case 0: (*ciphertext_len) = aes_ecb_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, key);
			break;
		case 1: (*ciphertext_len) = aes_cbc_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, key, iv);
			break;
	}

	// return dice value to allow for verification later on
	return dice;
}

unsigned int aes_encryption_random2(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_header, unsigned int random_header_len, unsigned char *random_key)
{
	unsigned char *unknown_str_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	unsigned char *unknown_str;
	unsigned int unknown_str_len;
	unknown_str_len = base64decode(&unknown_str, unknown_str_b64, strlen(unknown_str_b64));
	unknown_str[unknown_str_len] = '\0';

// 	srand((unsigned int)time(NULL));
// 	unsigned int header_len = rand() % 64;
// 	unsigned char header[header_len];
	unsigned int i;

// 	// initialize header
// 	for(i=0; i<header_len; i++) {
// 		header[i] = 32 + rand() % 224;
// 	}

	unsigned int plaintext_mod_len = random_header_len + plaintext_len + unknown_str_len;
	unsigned char plaintext_mod[plaintext_mod_len];

	// assemble plaintext string
	// header
	for(i=0; i<random_header_len; i++) {
		plaintext_mod[i] = random_header[i];
	}
	// plaintext
	for(i=0; i<plaintext_len; i++) {
		plaintext_mod[random_header_len+i] = plaintext[i];
	}
	// append unknown string
	for(i=0; i<unknown_str_len; i++) {
		plaintext_mod[random_header_len+plaintext_len+i] = unknown_str[i];
	}

	// PKCS#7 padding
	unsigned int plaintext_mod_padded_len = plaintext_mod_len + (16 - ((plaintext_mod_len) % 16));
	unsigned char plaintext_mod_padded[plaintext_mod_padded_len];

	plaintext_mod_padded_len = pkcs7_padding(plaintext_mod_padded, plaintext_mod, plaintext_mod_len, 16);

	unsigned int ciphertext_len = aes_ecb_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, random_key);

	free(unknown_str);

	return ciphertext_len;
}

unsigned int aes_encryption_random(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key)
{
	unsigned char *unknown_str_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	unsigned char *unknown_str;
	unsigned int unknown_str_len;
	unknown_str_len = base64decode(&unknown_str, unknown_str_b64, strlen(unknown_str_b64));
	unknown_str[unknown_str_len] = '\0';

	unsigned int plaintext_mod_len = plaintext_len + unknown_str_len;
	unsigned char plaintext_mod[plaintext_mod_len];

	unsigned int i;

	// assemble plaintext string
	// plaintext
	for(i=0; i<plaintext_len; i++) {
		plaintext_mod[i] = plaintext[i];
	}
	// append unknown string
	for(i=0; i<unknown_str_len; i++) {
		plaintext_mod[plaintext_len+i] = unknown_str[i];
	}

	// PKCS#7 padding
	unsigned int plaintext_mod_padded_len = plaintext_mod_len + (16 - ((plaintext_mod_len) % 16));
	unsigned char plaintext_mod_padded[plaintext_mod_padded_len];

	plaintext_mod_padded_len = pkcs7_padding(plaintext_mod_padded, plaintext_mod, plaintext_mod_len, 16);

	unsigned int ciphertext_len = aes_ecb_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, random_key);

	free(unknown_str);

	return ciphertext_len;
}

unsigned int is_ecb_mode(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned int block_len)
{
	double hn = 0.0;

	hn = norm_hamming_distance(ciphertext, ciphertext_len, block_len);

// 	printf("hn=%f\n", hn);

	if(hn < 2.5)
		return 0;	// ECB mode encrypted cipher detected
	else if(hn > 3)
		return 1;	// CBC mode (or maybe other?) detected

	return 2;	// unknown mode
}


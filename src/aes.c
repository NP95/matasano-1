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

unsigned int aes_ctr_crypt(unsigned char *crypted, unsigned char *uncrypted, unsigned int uncrypted_len, unsigned char *key, unsigned int nonce)
{
	unsigned int num_blocks = uncrypted_len / 16;
	unsigned int cnt = nonce;

	unsigned char keystream_plain[16];
	unsigned char keystream[16];

	unsigned int bytes_remaining = uncrypted_len;
	unsigned int bytes = 0;
	unsigned int len = 0;

	unsigned char *cipher_block;
	unsigned int i;

	for(i=0; i<num_blocks; i++) {
		// initialize keystream
		memset(keystream_plain, 0, 16*sizeof(unsigned char));
		keystream_plain[8] = (cnt % 256);

		// generate keystream
		aes_ecb_encrypt(128, keystream, keystream_plain, 16, key);

		// crypt block
		len = (bytes_remaining>=16) ? 16 : bytes_remaining;
		fixed_xor(&cipher_block, uncrypted+(i*16), keystream, len);
		memcpy(crypted+(i*16), cipher_block, 16*sizeof(unsigned char));
		bytes += len;
		bytes_remaining -= len;
		free(cipher_block);

		// increment counter
		cnt++;
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
		// fixed header len
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
		// fixed header len
		cipher_one_off_save_length = aes_encryption_random2(cipher_one_off_save, sendbuf, sendbuf_len-i-1, random_header, random_header_len, random_key);

		for(j=0; j<256; j++) {
			memset(sendbuf, 'B', sendbuf_len*sizeof(unsigned char));
			plaintext_one_off[ciphertext_length-1] = j;

			memcpy(sendbuf+prepad_size, plaintext_one_off, ciphertext_length*sizeof(unsigned char));
			// fixed header len
			cipher_one_off_length = aes_encryption_random2(cipher_one_off, sendbuf, sendbuf_len, random_header, random_header_len, random_key);

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

unsigned int aes_ecb_partial_crack3(unsigned char *plaintext, unsigned int *plaintext_length, unsigned int *key_length)
{
	unsigned char random_key[16];

	unsigned char ciphertext[1024];
	unsigned char exp_ciphertext[1024];
	unsigned char *ciphertext_hex;
	unsigned int ciphertext_length;
	unsigned char known_plaintext[1024];
	unsigned int i, j, k;
	unsigned int prepad_size = 0;
	unsigned char check_buf[32];

	// initialize key length
	(*key_length) = 0;

	// initialize random encryption key
	aes_random_key(random_key, 16);
	(*key_length) = 16;

	// determine minimum ciphertext_len
	// --> assumption here is, that no garbage header bytes
	//     were added
	unsigned int exp_length = UINT_MAX;
	unsigned int tmp_length = 0;

	// make sure to use some check_byte that IS DEFINITELY NOT
	// included in the random header,
	// otherwise aes_encryption_random3_sane() might in some rare
	// cases return a ciphertext containing random data!
	memset(check_buf, 0, 32*sizeof(unsigned char));
	for(j=0; j<16; j++) {
		for(i=0; i<2000; i++) {
			tmp_length = aes_encryption_random3(ciphertext, check_buf, 16+j, random_key);
			if((tmp_length-j-16) < exp_length) {
				prepad_size = j;
				exp_length = tmp_length-j-16;
				memcpy(exp_ciphertext, ciphertext, exp_length+prepad_size+16);
			}
		}
	}

	printf("[s2c6] Expected ciphertext length=%d, pad_len=%d\n", exp_length, prepad_size);

	// first 'identification block' + pad bytes for full block alignment + ciphertext
	ciphertext_length=exp_length+prepad_size+16;
	unsigned char buf[ciphertext_length];

	// now on to the crckng!
	unsigned char plaintext_one_off[ciphertext_length];

	unsigned char cipher_one_off_save[1024];
	unsigned char *coos;
	unsigned int cipher_one_off_save_length;

	unsigned char cipher_one_off[1024];
	unsigned char *coo;
	unsigned int cipher_one_off_length;

	(*plaintext_length) = 0;

	for(i=0; i<exp_length; i++) {
		memset(plaintext_one_off, 0, (ciphertext_length-i-1)*sizeof(unsigned char));
		for(j=ciphertext_length-i-1, k=0; j<ciphertext_length-1; j++, k++) {
			plaintext_one_off[j] = plaintext[k];
		}

		memset(cipher_one_off_save, 0, 1024*sizeof(unsigned char));
		// dynamic header len
		cipher_one_off_save_length = aes_encryption_random3_sane(cipher_one_off_save, exp_ciphertext, exp_length, plaintext_one_off, ciphertext_length-i-1, random_key);
// 		hex_encode(&coos, cipher_one_off_save, ciphertext_length);
// 		printf("[s2c6] coos   = '%s'\n", coos);
// 		free(coos);

// 		printf("byte %d\n", i);
		for(j=0; j<256; j++) {
			plaintext_one_off[ciphertext_length-1] = j;

			// dynamic header len
			cipher_one_off_length = aes_encryption_random3_sane(cipher_one_off, exp_ciphertext, exp_length, plaintext_one_off, ciphertext_length, random_key);
// 			printf("[%d] cipher_len = %d, saved_len = %d, cur_len = %d\n", j, ciphertext_length, cipher_one_off_save_length, cipher_one_off_length);
// 			hex_encode(&coo, cipher_one_off, ciphertext_length);
// 			printf("[s2c6] c(%03d) = '%s'\n", j, coo);
// 			free(coo);

			// compare to saved one-off cipher
			if(memcmp(cipher_one_off, cipher_one_off_save, ciphertext_length)==0) {
				plaintext[i] = plaintext_one_off[ciphertext_length-1];
// 				printf("[s2c6] P[%d] = %c\n", i, plaintext[i]);
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
	for(i=0; i<plaintext_len; i++) {
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

unsigned int aes_encryption_random3_sane(unsigned char *sane_ciphertext, unsigned char *expected_ct, unsigned int expected_ct_length, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key)
{
	// TODO: Assure that *NEVER* a ciphertext containing random
	// bytes is returned.
	// In rare circumstances this is the case, *IF* the expected_ct
	// consists of chars that can occur in the random header (which
	// in general might be the case).
	// This now works, because chars below 32d never appear as random
	// header data and expected_ct is set to all 0d.
	unsigned int ciphertext_len=UINT_MAX;

	unsigned int e_len = expected_ct_length + plaintext_len;
	memset(sane_ciphertext, 0, 16*sizeof(unsigned char));
	
	// make sure we're looking for multiples of the block size
	// otherwise we're gonna run forever...
	while((e_len % 16) != 0)
		e_len++;

	// detect minimum block size
	while(((ciphertext_len)>e_len) || (memcmp(sane_ciphertext, expected_ct, 16*sizeof(unsigned char))!=0)) {
		ciphertext_len = aes_encryption_random3(sane_ciphertext, plaintext, plaintext_len, random_key);
	}

	return ciphertext_len;
}

unsigned int aes_encryption_random3(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key)
{
	unsigned char *unknown_str_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	unsigned char *unknown_str;
	unsigned int unknown_str_len;
	unknown_str_len = base64decode(&unknown_str, unknown_str_b64, strlen(unknown_str_b64));
	unknown_str[unknown_str_len] = '\0';

// 	srand((unsigned int)time(NULL));
	unsigned int random_header_len = rand() % 64;
	unsigned char random_header[random_header_len];
	unsigned int i;

// 	// initialize header
// 	printf("[s2c6] random_header_len = %d\n", random_header_len);
	for(i=0; i<random_header_len; i++) {
		random_header[i] = 32 + rand() % 224;
	}

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

	memset(ciphertext, 0, plaintext_mod_padded_len*sizeof(unsigned char));
	unsigned int ciphertext_len = aes_ecb_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, random_key);

	free(unknown_str);

	return ciphertext_len;
}

unsigned int aes_encryption_random2(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_header, unsigned int random_header_len, unsigned char *random_key)
{
	unsigned char *unknown_str_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	unsigned char *unknown_str;
	unsigned int unknown_str_len;
	unknown_str_len = base64decode(&unknown_str, unknown_str_b64, strlen(unknown_str_b64));
	unknown_str[unknown_str_len] = '\0';

	unsigned int i;

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

unsigned int aes_cbc_oracle(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key, unsigned char *iv)
{
	unsigned char *header = "comment1=cooking%20MCs;userdata="; // 32
	unsigned char *trailer = ";comment2=%20like%20a%20pound%20of%20bacon"; // 42

	unsigned char plaintext_san[plaintext_len];

	unsigned char complete_pt[plaintext_len+32+42];
	unsigned int i;

	// sanitize input
	for(i=0; i<plaintext_len; i++) {
		if(plaintext[i] == ';' || plaintext[i] == '=' )
			plaintext_san[i] = '_';
		else
			plaintext_san[i] = plaintext[i];
	}

	// assemble complete plaintext string
	memcpy(complete_pt, header, 32*sizeof(unsigned char));
	memcpy(complete_pt+32, plaintext_san, plaintext_len*sizeof(unsigned char));
	memcpy(complete_pt+32+plaintext_len, trailer, 42*sizeof(unsigned char));

	// perform PKCS#7 padding
	unsigned int plaintext_pad_len = 32 + plaintext_len + 42 + (16 - ((32+plaintext_len+42) % 16));
	unsigned char plaintext_pad[plaintext_pad_len];

	plaintext_pad_len = pkcs7_padding(plaintext_pad, complete_pt, 32+plaintext_len+42, 16);

	return aes_cbc_encrypt(128, ciphertext, plaintext_pad, plaintext_pad_len, random_key, iv);
}

unsigned int aes_ctr_oracle(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key, unsigned int nonce)
{
	unsigned char *header = "comment1=cooking%20MCs;userdata="; // 32
	unsigned char *trailer = ";comment2=%20like%20a%20pound%20of%20bacon"; // 42

	unsigned char plaintext_san[plaintext_len];

	unsigned char complete_pt[plaintext_len+32+42];
	unsigned int i;

	// sanitize input
	for(i=0; i<plaintext_len; i++) {
		if(plaintext[i] == ';' || plaintext[i] == '=' )
			plaintext_san[i] = '_';
		else
			plaintext_san[i] = plaintext[i];
	}

	// assemble complete plaintext string
	memcpy(complete_pt, header, 32*sizeof(unsigned char));
	memcpy(complete_pt+32, plaintext_san, plaintext_len*sizeof(unsigned char));
	memcpy(complete_pt+32+plaintext_len, trailer, 42*sizeof(unsigned char));

	return aes_ctr_crypt(ciphertext, complete_pt, 32+plaintext_len+42, random_key, nonce);
}

unsigned int aes_cbc_decrypt_check(unsigned char *plaintext_error, unsigned char *cipher, unsigned int cipher_len, unsigned char *key, unsigned char *iv)
{
	unsigned char plain[cipher_len];
	unsigned char plain_len = 0;

	unsigned int i=0, error=0;

	plain_len = aes_cbc_decrypt(128, plain, cipher, cipher_len, key, iv);

	// check result for invalid ASCII
	for(i=0; i<plain_len; i++) {
		if((plain[i] < 32) || (plain[i] > 127))
		{
			error = 1;
			break;
		}
	}

	if(error==0) {
		memset(plaintext_error, 0, cipher_len*sizeof(unsigned char));
		return 0;
	}
	else {
		memcpy(plaintext_error, plain, plain_len*sizeof(unsigned char));
		plaintext_error[plain_len] = 0;
		return plain_len;
	}
}

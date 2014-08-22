#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/pkcs.h"
#include "../include/hex2base64.h"
#include "../include/histogram.h"

unsigned int aes_cbc_padding_oracle(unsigned char *ciphertext, unsigned char *key, unsigned char *iv)
{
	unsigned char *strings[10] = {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
	};

	unsigned char *string_b64 = strings[rand() % 10];
	unsigned char *string;
	unsigned int string_len;

	// base64 decode
	string_len = base64decode(&string, string_b64, strlen(string_b64));
	string[string_len] = '\0';

	// perform PKCS#7 padding
	unsigned int str_pad_len = string_len + (16 - (string_len % 16));
	unsigned char str_pad[str_pad_len];

	str_pad_len = pkcs7_padding(str_pad, string, string_len, 16);

	free(string);

	// cbc encrypt
	return aes_cbc_encrypt(128, ciphertext, str_pad, str_pad_len, key, iv);
}

int aes_cbc_padding_oracle_decrypt(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	unsigned char plain[ciphertext_len];
	unsigned int plain_len;

	// decrypt
	plain_len = aes_cbc_decrypt(128, plain, ciphertext, ciphertext_len, key, iv);

	// PKCS#7 unpad
	unsigned char unpad[plain_len];

	return pkcs7_unpadding(unpad, plain, plain_len, 16);
}

unsigned int aes_cbc_padding_oracle_attack(unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	// NOTE: we're not going to use the key here
	// it is directly passed to the decryption routine
	int is_valid;
	unsigned int num_blocks = ciphertext_len / 16;
	unsigned char cipher_mod[ciphertext_len];
	unsigned int cipher_mod_len;
	unsigned char *ciphertext_hex;
	unsigned char plain_xor[ciphertext_len];

	int j, m;
	unsigned int i, k, l, hits=0, cnt=0;

// 	hex_encode(&ciphertext_hex, ciphertext, ciphertext_len);
// 	printf("[%02d] cipher = '%s'\n", 0, ciphertext_hex);
// 	free(ciphertext_hex);

	for(i=num_blocks; i>=1; i--) {
		// assemble modded ciphertext
		if(i>1) {
			l=0;
			cipher_mod_len = i*16;
			memcpy(cipher_mod, ciphertext, cipher_mod_len*sizeof(unsigned char));
			memset(cipher_mod+cipher_mod_len-32, 0, 16*sizeof(unsigned char));
		}
		else {
			l=1;
			cipher_mod_len = (i+1)*16;
			memset(cipher_mod, 0, cipher_mod_len*sizeof(unsigned char));
			memcpy(cipher_mod+16, ciphertext, 16*sizeof(unsigned char));
		}

		// iterate over byte position of n-1 ciphertext block
		for(j=15; j>=0; j--) {
			cnt++;

			// brute force
			for(k=0; k<256; k++) {
				cipher_mod[(i-2+l)*16+j] = k;
				is_valid = aes_cbc_padding_oracle_decrypt(cipher_mod, cipher_mod_len, key, iv);
				if(is_valid>0) {
					hits++;
					plain_xor[(i-1)*16+j] = (16-j) ^ k;
					// update solved ciphertext bits to match
					// next padding
					for(m=15; m>=j; m--) {
						cipher_mod[(i-2+l)*16+m] ^= (16-j) ^ ((16-j)+1);
					}
					break;
				}
			}

// 			hex_encode(&ciphertext_hex, cipher_mod, cipher_mod_len);
// 			printf("[%02d] cipher = '%s'\n", j, ciphertext_hex);
// 			free(ciphertext_hex);
		}
	}
	
// 	printf("len=%d, hits=%d, cnt=%d\n", ciphertext_len, hits, cnt);

	hex_encode(&ciphertext_hex, plain_xor, ciphertext_len);
// 	printf("[%02d] plain_xor = '%s'\n", 0, ciphertext_hex);
	free(ciphertext_hex);

	unsigned char *plain;
	unsigned char cipher_shift[ciphertext_len];

	memset(cipher_shift, 0, ciphertext_len);
	memcpy(cipher_shift, iv, 16*sizeof(unsigned char));
	memcpy(cipher_shift+16, ciphertext, (ciphertext_len-16)*sizeof(unsigned char));

// 	hex_encode(&ciphertext_hex, cipher_shift, ciphertext_len);
// 	printf("[%02d] cipher_sh = '%s'\n", 0, ciphertext_hex);
// 	free(ciphertext_hex);

	fixed_xor(&plain, cipher_shift, plain_xor, ciphertext_len);
	
	// remove PKCS#7 padding
	unsigned char unpad[ciphertext_len+1];
	unsigned int unpad_len;

	unpad_len = pkcs7_unpadding(unpad, plain, ciphertext_len, 16);
	memcpy(plaintext, unpad, unpad_len*sizeof(unsigned char));

	free(plain);

	return unpad_len;
}

int main(void) {
	// init rng
	srand((unsigned int) time(NULL));
	
	// init key, iv
	unsigned char key[16], iv[16];

	aes_random_key(key, 16);
	aes_random_key(iv, 16);

	/** Set 3 Challenge 17 **/
	/** CBC Padding Oracle **/
	unsigned char s3c1_cipher[128];
	unsigned int s3c1_cipher_len;

	// call oracle
	s3c1_cipher_len = aes_cbc_padding_oracle(s3c1_cipher, key, iv);

	// call decrypter
	int is_valid;

	is_valid = aes_cbc_padding_oracle_decrypt(s3c1_cipher, s3c1_cipher_len, key, iv);
	printf("[s3c1] valid ... [%s]\n", (is_valid>0) ? "yes": "no");

	// attack
	unsigned char s3c1_plain[s3c1_cipher_len+1];
	memset(s3c1_plain, 0, (s3c1_cipher_len+1)*sizeof(unsigned char));

	aes_cbc_padding_oracle_attack(s3c1_plain, s3c1_cipher, s3c1_cipher_len, key, iv);

	printf("[s3c1] plain = '%s'\n", s3c1_plain);

	/** Set 3 Challenge 18 **/
	/**  CTR  CIPHER MODE  **/
	unsigned char s3c2_in_b64[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

	unsigned char *s3c2_in;
	unsigned int s3c2_in_len;

	unsigned char s3c2_plain[128];
	unsigned int s3c2_plain_len;
	memset(s3c2_plain, 0, 128*sizeof(unsigned char));
	
	// base64 decode
	s3c2_in_len = base64decode(&s3c2_in, s3c2_in_b64, strlen(s3c2_in_b64));
// 	s3c2_in[s3c2_in_len] = '\0';
	
	// crypt
	strncpy(key, "YELLOW SUBMARINE", 16);
	s3c2_plain_len = aes_ctr_crypt(s3c2_plain, s3c2_in, s3c2_in_len, key, 0);
// 	s3c2_plain[s3c2_plain_len] = '\0';

	printf("[s3c2] plain = '%s'\n", s3c2_plain);
	free(s3c2_in);

	/**    Set 3 Challenge 19     **/
	/** CTR STATIC NONCE CRACKING **/
	unsigned char *s3c3_plain_b64[40] = {
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
	};
	unsigned char *s3c3_plain[40];
	unsigned int s3c3_plain_len[40];
	unsigned char s3c3_cipher[40][128];
	unsigned char *s3c3_cipher_hex[40];
	unsigned int s3c3_cipher_len[40];
	// first block transposed
	unsigned char s3c3_cipher_trans[32][40];
	unsigned char *s3c3_plain_trans[32];

	unsigned char ks[32];
	unsigned int i, j;

	// generate random key
	aes_random_key(key, 16);

	// encrypt strings
	for(i=0; i<40; i++) {
		// base64 decode
		s3c3_plain_len[i] = base64decode(&s3c3_plain[i], s3c3_plain_b64[i], strlen(s3c3_plain_b64[i]));

		// aes ctr crypt
		s3c3_cipher_len[i] = aes_ctr_crypt(s3c3_cipher[i], s3c3_plain[i], s3c3_plain_len[i], key, 0);

		// free plain
		free(s3c3_plain[i]);
	}

	// crckng...
	for(i=0; i<40; i++) {
		// transpose
// 		for(j=0; j<16; j++) {
		for(j=0; j<s3c3_cipher_len[i]; j++) {
			s3c3_cipher_trans[j][i] = s3c3_cipher[i][j];
		}

		// debug print orig ciphertexts
		hex_encode(&s3c3_cipher_hex[i], s3c3_cipher[i], s3c3_cipher_len[i]);
		printf("[s3c3] %02d: len=%2d, %s\n", i, s3c3_cipher_len[i], s3c3_cipher_hex[i]);
		free(s3c3_cipher_hex[i]);
	}

	max_hist_t hist;
	max_hist2_t hist2;
	max_hist3_t hist3;

	for(j=0; j<32; j++) {
		// debug print transposed ciphertexts
		hex_encode(&s3c3_cipher_hex[j], s3c3_cipher_trans[j], 40);
		printf("[s3c3] %02d: %s\n", j, s3c3_cipher_hex[j]);
		free(s3c3_cipher_hex[j]);
		// generate histograms
		init_histogram(&hist);
		init_histogram2(&hist2);
		init_histogram3(&hist3);
		hist = histogram(s3c3_cipher_trans[j], 40, 0);
		hist2 = histogram2(s3c3_cipher_trans[j], 40, 0);
		hist3 = histogram3(s3c3_cipher_trans[j], 40, 0);
		for(i=0; i<HIST_DEPTH; i++) {
			/**** SINGLE BYTE CRCKNG ****/
			// skip obviously wrong counts occuring in messages
			// with 2 blocks (we've got loads of 0x00 in the
			// transposed ciphertexts, so discard them
			if((hist.num[i] > 30) && (hist.byte[i] == 0x00))
				continue;
			// guess keystream
			switch(j) {
				// we don't start with spaces, right?
				case 0: ks[j] = hist.byte[i] ^ 0x54;
					 break;
				default: ks[j] = hist.byte[i] ^ 0x20;
					 break;
			}
			xor_key(&s3c3_plain_trans[j], s3c3_cipher_trans[j], 40, &ks[j], 1);
			// validate by analyzing produced plaintext
			if(is_cleartext(s3c3_plain_trans[j], 40)==0) {
				break;
				free(s3c3_plain_trans[j]);
			}
			free(s3c3_plain_trans[j]);
			/**** ****************** ****/
			/**** DOUBLE BYTE CRCKNG ****//*
			if((hist2.num[i] > 10) &&
			   (hist2.byte[i][0] == 0x00) &&
			   (hist2.byte[i][1] == 0x00))
				continue;

			if(j<31) {
				ks[j] = hist2.byte[i][0] ^ 'e';
				ks[j+1] = hist2.byte[i][1] ^ ' ';
				xor_key(&s3c3_plain_trans[j], s3c3_cipher_trans[j], 40, &ks[j], 2);
				// validate by analyzing produced plaintext
				if(is_cleartext(s3c3_plain_trans[j], 40)==0) {
					break;
					free(s3c3_plain_trans[j]);
				}
				free(s3c3_plain_trans[j]);
			}
			*//**** ****************** ****/
			/**** TRIPLE BYTE CRCKNG ****//*
			if((hist3.num[i] > 5) &&
			   (hist3.byte[i][0] == 0x00) &&
			   (hist3.byte[i][1] == 0x00) &&
			   (hist3.byte[i][2] == 0x00))
				continue;

			if(j<30) {
				ks[j] = hist3.byte[i][0] ^ 't';
				ks[j+1] = hist3.byte[i][1] ^ 'h';
				ks[j+2] = hist3.byte[i][2] ^ 'e';
				xor_key(&s3c3_plain_trans[j], s3c3_cipher_trans[j], 40, &ks[j], 3);
				// validate by analyzing produced plaintext
				if(is_cleartext(s3c3_plain_trans[j], 40)==0) {
					break;
					free(s3c3_plain_trans[j]);
				}
				free(s3c3_plain_trans[j]);
			}
			*//**** ****************** ****/
		}
	}

	// decrypt
	for(j=0; j<40; j++) {
		fixed_xor(&s3c3_plain[j], s3c3_cipher[j], ks, s3c3_cipher_len[j]);
		s3c3_plain[j][s3c3_cipher_len[j]] = 0;
		printf("[s3c3] %02d: plain = '%s'\n", j, s3c3_plain[j]);
		free(s3c3_plain[j]);
	}

	return 0;
}

#include <stdio.h>
// #include <openssl/aes.h>

#include "../include/aes.h"
#include "../include/hex2base64.h"
#include "../include/hex_coder.h"
#include "../include/xor.h"
#include "../include/histogram.h"
#include "../include/hamming.h"

int main(void){
	/***  Set 1 Challenge 1  ***/
	/*** HEX to BASE64 CODER ***/
	printf("*** SET 1 - CHALLENGE 1\n*** HEX to BASE64 CODER\n\n");
	char *str_to_encode = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	unsigned char *data_to_encode;  //A null terminated string to be base-64 encoded.
// 	int bytes_to_encode = sizeof(data_to_encode) - 1; //Number of bytes in string (minus null).
	int bytes_to_encode = hex_decode(&data_to_encode, str_to_encode, strlen(str_to_encode)); //Number of bytes in string (minus null).
	char * base64data = base64encode(data_to_encode, bytes_to_encode);  //Base-64 encodes data.
	unsigned char * orig_data;

	base64decode(&orig_data, base64data, strlen(base64data));  //Base-64 decodes data.
	
	printf("Original character string is: %s\n", data_to_encode);  //Prints our initial string.
	printf("Base-64 encoded string is: %s\n", base64data);  //Prints our Base64 encoded string.
	printf("Original character string is: %s\n", orig_data);  //Prints our initial string.
	
	free(orig_data);
	free(data_to_encode);
	free(base64data);  //Frees up the memory holding our base64 encoded data.

	/*** Set 1 Challenge 2 ***/
	/***     Fixed XOR     ***/
	printf("\n*** SET 1 - CHALLENGE 2\n*** FIXED XOR\n\n");
	char *data_str = "1c0111001f010100061a024b53535009181c";
	char *key_str = "686974207468652062756c6c277320657965";
	unsigned char *xor_str = 0;

	unsigned char *data = 0;
	unsigned char *key = 0;
	unsigned char *xored_out = 0;

	hex_decode(&data, data_str, strlen(data_str));
	bytes_to_encode = hex_decode(&key, key_str, strlen(key_str));

	fixed_xor(&xored_out, data, key, bytes_to_encode);

	hex_encode(&xor_str, xored_out, bytes_to_encode);

	printf("fixed_xor[str] = '%s'\nfixed_xor[hex] = '%s'\n", xored_out, xor_str);

	free(xor_str);
	free(data);
	free(key);

	/*** Set 1 Challenge 3 ***/
	/***  Single-Byte XOR  ***/
	printf("\n*** SET 1 - CHALLENGE 3\n*** SINGLE-BYTE XOR\n\n");
	char *cipher_text_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

	unsigned char *cipher_text;
	unsigned int i, k=0;
	unsigned char match[] = "etaoin shrdlu\0";
	max_hist_t e;
	bytes_to_encode = hex_decode(&cipher_text, cipher_text_str, strlen(cipher_text_str));

	printf("cipher[hex] = '%s'\ncipher[str] = '%s'\n", cipher_text_str, cipher_text);

	init_histogram(&e);
	e = histogram(cipher_text, bytes_to_encode, 1);
	printf("match[i] ?= 0x%02x\n", e.byte[0]);

	key = malloc(bytes_to_encode+1);
	memset(key, 0, bytes_to_encode+1);
	// p ^ k = c, c ^ k = p => c ^ p = k
	// calculate key
	k = e.byte[0] ^ 0x20;
	memset(key, k, bytes_to_encode);

	printf("key[str] = '%s'\n", key);

	unsigned char *clear_text;

	fixed_xor(&clear_text, cipher_text, key, bytes_to_encode);

	printf("clear[str] = '%s'\n", clear_text);

	free(clear_text);
	free(key);
	free(cipher_text);

	/***   Set 1 Challenge 4    ***/
	/*** DETECT SINGLE-CHAR XOR ***/
	printf("\n*** SET 1 - CHALLENGE 4\n*** SINGLE-CHAR XOR DETECTION\n\n");

	FILE *fp;
	char *line_str = NULL;
	unsigned char *line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen("4.txt", "r");

	if(fp==NULL)
		return -1;

	init_histogram(&e);
	i=0;
	while((read = getline(&line_str, &len, fp)) != -1) {
		bytes_to_encode = hex_decode(&line, line_str, strlen(line_str));

		e = histogram(line, bytes_to_encode, 0);

		// just look at the interesting lines
		if(e.num[0] > 4) {
			if(attack_single_byte_xor(&clear_text, &key, line, bytes_to_encode)==0) {
				printf("key[str] = '%s'\n", key);
				printf("clear[str] = '%s'\n", clear_text);
			}

			free(clear_text);
			free(key);
		}

		i++;

		free(line);
	}

	if(line_str)
		free(line_str);
	close(fp);

	/*** Set 1 Challenge 5 ***/
	/*** REPEATING-KEY XOR ***/
	printf("\n*** SET 1 - CHALLENGE 5\n*** REPEATING-KEY XOR\n\n");

	unsigned char *s1c5_clear = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal\0";
	unsigned char *s1c5_key = "ICE";
	unsigned char *s1c5_cipher;
	unsigned char *s1c5_cipher_hex;

	xor_key(&s1c5_cipher, s1c5_clear, strlen(s1c5_clear), s1c5_key, strlen(s1c5_key));
	hex_encode(&s1c5_cipher_hex, s1c5_cipher, strlen(s1c5_cipher));

// 	printf("s1c5_cipher[str] = '%s'\n", s1c5_cipher);
	printf("s1c5_cipher[hex] = '%s'\n", s1c5_cipher_hex);

	free(s1c5_cipher);

	/***     Set 1 Challenge 6      ***/
	/*** BREAKING REPEATING-KEY XOR ***/
	printf("\n*** SET 1 - CHALLENGE 6\n*** BREAKING REPEATING-KEY XOR\n\n");

	unsigned int hamming = 0;
	unsigned int keysize = 2;
	hamming = hamming_distance("this is a test", "wokka wokka!!!", 15);
	printf("hamming('this is a test', 'wokka wokka!!!') = %d\n", hamming);

	unsigned char s1c6_cipher_b64[4192], *s1c6_cipher_line;
	unsigned char *s1c6_cipher;
	unsigned int s1c6_cipher_len = 0;
	char *s1c6_cipher_hex;
	unsigned char *tmp1;
	unsigned char *tmp2;
	double hamming_norm = 0.0;

	fp = fopen("6.txt", "r");
	len=0;

	if(fp==NULL)
		return -1;

	init_histogram(&e);
	while((read = getline(&line_str, &len, fp)) != -1) {
		for(i=0; i<read-1; i++) {
			s1c6_cipher_b64[s1c6_cipher_len+i] = line_str[i];
		}
		s1c6_cipher_len += read-1;
	}

	s1c6_cipher_b64[s1c6_cipher_len] = '\0';
// 	printf("s1c6_cipher_b64 = {\n%s\n}\n\n", s1c6_cipher_b64);
	bytes_to_encode = base64decode(&s1c6_cipher, s1c6_cipher_b64, s1c6_cipher_len);
	s1c6_cipher_len = bytes_to_encode;

	if(line_str)
		free(line_str);
	close(fp);

// 	hex_encode(&s1c6_cipher_hex, s1c6_cipher, s1c6_cipher_len);
// 	printf("s1c6_cipher[str] = '%s'\n", s1c6_cipher_hex);
// 	free(s1c6_cipher_hex);

// 	char *tmp1_hex;
// 	char *tmp2_hex;
	/** determine keysize **/
	unsigned int res_keysize = 0;
	double	res_dist=10;
	unsigned int num_tmp=0;

	for(keysize=2; keysize<41; keysize++) {
		hamming_norm = norm_hamming_distance(s1c6_cipher, s1c6_cipher_len, keysize);
// 		printf("hamming_norm(keysize=%d) = %f\n", keysize, hamming_norm);

		if(hamming_norm < res_dist) {
			res_dist = hamming_norm;
			res_keysize = keysize;
		}
	}

	printf("keysize = %d (dist_norm = %f)\n", res_keysize, res_dist);

	/** break up ciphertext into keysize blocks **/
	/** and transpose the whole shit xD **/
	unsigned int j;
	unsigned int num_blocks = s1c6_cipher_len / res_keysize;
	printf("num_blocks = %d\n", num_blocks);

	unsigned char blocks[res_keysize][num_blocks];
	char *block_hex;

	// transpose
	for(j=0; j<res_keysize; j++) {
		for(i=1; i<=num_blocks; i++) {
			blocks[j][i-1] = s1c6_cipher[j+res_keysize*(i-1)];
		}
	}

	unsigned char complete_key[res_keysize];

	for(i=0; i<res_keysize; i++) {
// 		hex_encode(&block_hex, blocks[i], num_blocks);
// 		printf("block[%d] = '%s'\n", i, block_hex);
// 		free(block_hex);

		if(attack_single_byte_xor(&clear_text, &key, blocks[i], num_blocks) == 0) {
// 			printf("[%d] block_clear[%d] = '%s'\n", res_keysize, i, clear_text);
// 			printf("[%d] block_key[%d] = '%c'\n", res_keysize, i, key[0]);
			complete_key[i] = key[0];
		}

		free(clear_text);
		free(key);
	}
	complete_key[res_keysize] = '\0';
	printf("key = '%s'\n", complete_key);

	xor_key(&clear_text, s1c6_cipher, s1c6_cipher_len, complete_key, res_keysize);

	printf("clear_text = {\n%s\n}\n\n", clear_text);

	free(clear_text);
	free(s1c6_cipher);
// 	printf("%d\n", is_cleartext("Cooking MC's like a pound of bacon", 34));
// 	printf("%d\n", is_cleartext("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 34));

	/*** SET 1 - Challenge 7 ***/
	/***   AES in ECB mode   ***/
	printf("*** SET 1 - CHALLENGE 7\n");
	printf("*** AES in ECB mode\n\n");

	fp = fopen("7.txt", "r");

	if(fp==NULL)
		return -1;

	len=0;
	s1c6_cipher_len=0;
	while((read = getline(&line_str, &len, fp)) != -1) {
		for(i=0; i<read-1; i++) {
			s1c6_cipher_b64[s1c6_cipher_len+i] = line_str[i];
		}
		s1c6_cipher_len += read-1;
	}

	s1c6_cipher_b64[s1c6_cipher_len] = '\0';
// 	printf("s1c6_cipher_b64 = {\n%s\n}\n\n", s1c6_cipher_b64);
	bytes_to_encode = base64decode(&s1c6_cipher, s1c6_cipher_b64, s1c6_cipher_len);
	s1c6_cipher_len = bytes_to_encode;

	if(line_str)
		free(line_str);
	close(fp);

	key = malloc(17);
	memset(key, 0, 17);
	strcpy(key, "YELLOW SUBMARINE");
	printf("key = '%s'\n", key);

	clear_text = malloc(s1c6_cipher_len);
	memset(clear_text, 0, s1c6_cipher_len);

	bytes_to_encode = aes_ecb_decrypt(128, clear_text, s1c6_cipher, s1c6_cipher_len, key);
	bytes_to_encode = aes_ecb_encrypt(128, s1c6_cipher, clear_text, bytes_to_encode, key);
	memset(clear_text, 0, bytes_to_encode);
	aes_ecb_decrypt(128, clear_text, s1c6_cipher, bytes_to_encode, key);
// 	aes_ecb_decrypt(128, clear_text, s1c6_cipher, s1c6_cipher_len, key);

	printf("clear_text = '%s'\n", clear_text);

	free(s1c6_cipher);
	free(clear_text);
	free(key);

	/***    SET 1 - Challenge 8    ***/
	/*** AES in ECB mode DETECTION ***/
	printf("\n*** SET 1 - CHALLENGE 8\n");
	printf("*** AES in ECB mode DETECTION\n\n");

	fp = fopen("8.txt", "r");

	if(fp==NULL)
		return -1;

	len=0;
	s1c6_cipher_len=0;
	num_blocks = 0;
	res_dist = 0;
	unsigned int line_cnt=1;
	unsigned int hits=0;
	while((read = getline(&line_str, &len, fp)) != -1) {
		s1c6_cipher_len = hex_decode(&s1c6_cipher, line_str, read);
// 		printf("ciph(%d) = '%s'\n", s1c6_cipher_len, s1c6_cipher);
		hits = 0;
		num_blocks = s1c6_cipher_len / 16;
		for(i=0; i<num_blocks; i++) {
			for(j=1; j<num_blocks; j++) {
				for(k=0; k<16; k++) {
					if(s1c6_cipher[16*i+k]==s1c6_cipher[16*j+k])
						hits++;
				}
			}
		}

		if(hits > res_dist) {
			res_dist = hits;
			res_keysize = line_cnt;
		}
		printf("[%d] hits = %d\n", line_cnt, hits);
		line_cnt++;

		free(s1c6_cipher);
	}

	printf("AES-ECB cipher found at line: %d\n", res_keysize);

	if(line_str)
		free(line_str);
	close(fp);
}


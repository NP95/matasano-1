#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "../include/httpget.h"
#include "../include/aes.h"
#include "../include/pkcs.h"
#include "../include/hex2base64.h"
#include "../include/histogram.h"
#include "../include/mac.h"

unsigned int aes_ctr_edit(unsigned char *edited_cipher, unsigned char *cipher, unsigned int cipher_len, unsigned char *key, unsigned int nonce, unsigned int offset, unsigned char *plaintext, unsigned int plaintext_len)
{
	if(offset >= cipher_len)
		return 0;

	unsigned int block_len = 16;
	unsigned int block_num = plaintext_len / block_len + 1;
	unsigned int start_block = offset / block_len;

	unsigned int uncrypted_len = block_num * block_len;
	unsigned int uncrypted_bytes;
	unsigned int decrypt_len = (plaintext_len > (cipher_len-block_len*start_block)) ? (cipher_len-block_len*start_block): uncrypted_len;

	unsigned char uncrypted[uncrypted_len];

	unsigned int i;

	// decrypt blocks that need editing
	uncrypted_bytes = aes_ctr_crypt(uncrypted, cipher+start_block*block_len, decrypt_len, key, nonce+start_block);

// 	printf("Uncrypted(%d) = {\n%s\n}\n", offset, uncrypted);

	// assemble new plaintext
	memcpy(uncrypted+(offset-start_block*block_len), plaintext, plaintext_len*sizeof(unsigned char));

// 	printf("New Plain(%d) = {\n%s\n}\n", offset, uncrypted);

	// encrypt new plaintext
	unsigned char edit_crypted[block_num*block_len];
	unsigned int edit_crypted_len = 0;

	edit_crypted_len = aes_ctr_crypt(edit_crypted, uncrypted, block_num*block_len, key, nonce+start_block);

	// put edited ciphertext in place
	memcpy(edited_cipher, cipher, cipher_len*sizeof(unsigned char));
	memcpy(edited_cipher+start_block*block_len, edit_crypted, edit_crypted_len*sizeof(unsigned char));

	unsigned int remaining_len = (plaintext_len > (cipher_len-offset)) ? plaintext_len : cipher_len-offset;

	return remaining_len+offset;
}

unsigned int aes_ctr_edit_crack(unsigned char *plaintext, unsigned char *cipher, unsigned int cipher_len, unsigned char *key, unsigned int nonce)
{
	unsigned char edit[cipher_len];

	unsigned int j, k;

	// init plaintext, key
	memset(plaintext, 0, cipher_len*sizeof(unsigned char));

	for(k=0; k<cipher_len-1; k++) {
		// bf plaintext byte
		for(j=0; j<256; j++) {
			plaintext[k] = j;

			aes_ctr_edit(edit, cipher, cipher_len, key, nonce, 0, plaintext, k+1);

			if(!memcmp(cipher, edit, k+1)) {
// 				printf("hit %d, %c\n", k, j);
				break;
			}
		}
	}

	return cipher_len;
}

int main(void)
{
	srand(time(NULL));

	/**           Set 4 Challenge 1           **/
	/** CRCK RANDOM READ/WRITE ACCESS AES CTR **/
	FILE *fp = fopen("25.txt", "r");

	if(fp==NULL)
		return -1;

	unsigned int i;
	unsigned char *cipher;
	unsigned char cipher_b64[8192];
	unsigned int cipher_len=0;
	char *line_str = NULL;
	size_t len=0;
	ssize_t read;
	while((read = getline(&line_str, &len, fp)) != -1) {
		for(i=0; i<read-1; i++) {
			cipher_b64[cipher_len+i] = line_str[i];
		}
		cipher_len += read-1;
	}

	if(line_str)
		free(line_str);
	close(fp);

	cipher_b64[cipher_len] = '\0';
	cipher_len = base64decode(&cipher, cipher_b64, cipher_len);

	unsigned char s4c1_plain[1024];
	unsigned int s4c1_plain_len = 0;
	memset(s4c1_plain, 0, 1024*sizeof(unsigned char));
	s4c1_plain_len = aes_ecb_decrypt(128, s4c1_plain, cipher, cipher_len, "YELLOW SUBMARINE");
	s4c1_plain[s4c1_plain_len] = 0;

	free(cipher);

	unsigned char s4c1_cipher_ctr[s4c1_plain_len];
	unsigned int s4c1_cipher_ctr_len = 0;

	unsigned int s4c1_nonce = rand();
	unsigned char s4c1_key[16];

	aes_random_key(s4c1_key, 16);

	s4c1_cipher_ctr_len = aes_ctr_crypt(s4c1_cipher_ctr, s4c1_plain, s4c1_plain_len, s4c1_key, s4c1_nonce);

	unsigned char s4c1_edit_crypt[s4c1_cipher_ctr_len];
	unsigned int s4c1_edit_crypt_len = 0;

	// we assume the aes_ctr_edit() function internally knows
	// key and nonce, so we provide it here (but we don't know it actually)
// 	s4c1_edit_crypt_len = aes_ctr_edit_crack(s4c1_edit_crypt, s4c1_cipher_ctr, s4c1_cipher_ctr_len, s4c1_key, s4c1_nonce);
// 	s4c1_edit_crypt[s4c1_edit_crypt_len] = 0;
// 	printf("[s4c1] recovered plain (%d) = '%s'\n", s4c1_edit_crypt_len, s4c1_edit_crypt);

	/** Set 4 Challenge 2 **/
	/** CTR BITFLIP ATTAX **/
	unsigned char *s4c2_plain = "12345:admin<true"; // 16
	unsigned char s4c2_key[16];
	unsigned int s4c2_nonce = rand();
	unsigned char s4c2_cipher_orig[128];
	unsigned int s4c2_cipher_orig_len;
	unsigned char s4c2_cipher_mod[128];
	unsigned int s4c2_cipher_mod_len;

	aes_random_key(s4c2_key, 16);
	s4c2_cipher_orig_len = aes_ctr_oracle(s4c2_cipher_orig, s4c2_plain, 16, s4c2_key, s4c2_nonce);
	
	memcpy(s4c2_cipher_mod, s4c2_cipher_orig, s4c2_cipher_orig_len);
	// flip bits in ciphertext block 2
	// prepending our controlled buffer
	s4c2_cipher_mod[37] ^= 0x01;
	s4c2_cipher_mod[43] ^= 0x01;

	// decrypt
	unsigned char s4c2_dec[128];
	unsigned int s4c2_dec_len;

	s4c2_dec_len = aes_ctr_crypt(s4c2_dec, s4c2_cipher_mod, s4c2_cipher_orig_len, s4c2_key, s4c2_nonce);
	printf("[s4c2] plain='%s'\n", s4c2_dec);

	/** Set 4 Challenge 3 **/
	/** CBC IV = KEY VULN **/
	unsigned char *s4c3_plain = "12345:admin<true"; // 16
	unsigned char s4c3_key[16];
	unsigned char s4c3_cipher_orig[128];
	unsigned int s4c3_cipher_orig_len;
	unsigned char s4c3_cipher_mod[128];
	unsigned int s4c3_cipher_mod_len;
	
	aes_random_key(s4c3_key, 16);

	// create ciphertext C1, C2, C3
	s4c3_cipher_orig_len = aes_cbc_oracle(s4c3_cipher_orig, s4c3_plain, 16, s4c3_key, s4c3_key);
	
	// modify ciphertext C1, C2, C3 -> C1, 0, C1
	memset(s4c3_cipher_mod, 0, s4c3_cipher_orig_len);
	memcpy(s4c3_cipher_mod, s4c3_cipher_orig, 16);
	memcpy(s4c3_cipher_mod+32, s4c3_cipher_orig, 16);

	// perform decrypt check
	unsigned char s4c3_dec[128];
	unsigned int s4c3_dec_len;

	s4c3_dec_len = aes_cbc_decrypt_check(s4c3_dec, s4c3_cipher_mod, s4c3_cipher_orig_len, s4c3_key, s4c3_key);

	// error detected?
	if(s4c3_dec_len != 0) {
		unsigned char *rec_key;
		fixed_xor(&rec_key, s4c3_dec, s4c3_dec+32, 16);

		unsigned char *key_hex;
		unsigned int key_hex_len = 0;
		unsigned char *rec_key_hex;
		unsigned int rec_key_hex_len = 0;

		key_hex_len = hex_encode(&key_hex, s4c3_key, 16);
		key_hex[key_hex_len] = 0;
		rec_key_hex_len = hex_encode(&rec_key_hex, rec_key, 16);
		rec_key_hex[rec_key_hex_len] = 0;

		printf("[s4c3] recovered key='%s', random key was: '%s'\n", rec_key_hex, key_hex);
		free(rec_key);
		free(key_hex);
		free(rec_key_hex);
	}
	else
		printf("[s4c3] No ASCII error detected!\n");

	/**        Set 4 Challenge 4       **/
	/** SHA-1 KEYED MAC IMPLEMENTATION **/
	unsigned int mac[5];

	sha1_secret_prefix_mac(mac, "Hello World", 11, "YELLOW SUBMARINE", 16);

	printf("[s4c4] sha1_mac = ");
	for(i=0; i<5; i++) {
		printf("%08x", mac[i]);
	}
	printf("\n");

	if(sha1_secret_prefix_mac_auth(mac, "Hello World", 11, "YELLOW SUBMARINE", 16) == 0)
		printf("[s4c4] sha1 secret MAC successfully authenticated!\n");
	else
		printf("[s4c4] sha1 secret MAC *NOT* authenticated!\n");

	sha1_secret_prefix_mac(mac, "Hello World", 11, "YELLOW_SUBMARINE", 16);

	printf("[s4c4] sha1_mac = ");
	for(i=0; i<5; i++) {
		printf("%08x", mac[i]);
	}
	printf("\n");

	if(sha1_secret_prefix_mac_auth(mac, "Hello World", 11, "YELLOW SUBMARINE", 16) == 0)
		printf("[s4c4] sha1 secret MAC successfully authenticated!\n");
	else
		printf("[s4c4] sha1 secret MAC *NOT* authenticated!\n");

	/**   Set 4 Challenge 5    **/
	/** SHA-1 KEYED MAC ATTACK **/
	unsigned char s4c5_pad[72];
	unsigned int s4c5_pad_len = 0;
// 	s4c5_pad_len = sha1_generate_padding(s4c5_pad, 93);

	// test padding function
// 	printf("[s4c5] test_pad(%d) = ", s4c5_pad_len);
// 	for(i=0; i<s4c5_pad_len; i++) {
// 		printf("%02x", s4c5_pad[i]);
// 	}
// 	printf("\n");

	// attack
	unsigned char *s4c5_msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"; // 77
	unsigned int s4c5_msg_len = strlen(s4c5_msg);

	unsigned int s4c5_msg_mac[5];

	unsigned char *s4c5_msg_forged;
	unsigned int s4c5_msg_forged_len;
	unsigned int s4c5_msg_mac_forged[5];

	unsigned int j;

	// calc original MAC
	sha1_secret_prefix_mac(s4c5_msg_mac, s4c5_msg, s4c5_msg_len, "YELLOW SUBMARINE!", 17);
	printf("[s4c5] orig. msg_mac = ");
	for(i=0; i<5; i++) {
		printf("%08x", s4c5_msg_mac[i]);
	}
	printf("\n");

	unsigned char *forged_ext = ";admin=true"; // 11
	unsigned int forged_ext_len = strlen(forged_ext);

	unsigned char *forge_complete;

	unsigned int ext_pad_len = 0;
	unsigned char ext_pad[72];
	unsigned int pad_len = 0;
	unsigned char pad[72];

	unsigned int forge_str_len = 0;
	unsigned char *forge_str;

	//              MSG LEN      +  PAD_LEN                   +  EXTENSION
	forge_str_len = s4c5_msg_len + (64 - (s4c5_msg_len % 64)) + forged_ext_len;
// 	printf("[s4c5] forge_str_len = %d\n", forge_str_len);
	
	// generate extension padding
	ext_pad_len = sha1_generate_padding(ext_pad, forge_str_len);

	forge_complete = malloc((forged_ext_len+ext_pad_len)*sizeof(unsigned char));
	memcpy(forge_complete, forged_ext, forged_ext_len*sizeof(unsigned char));
	memcpy(forge_complete+forged_ext_len, ext_pad, ext_pad_len*sizeof(unsigned char));

	// calc MAC for message with forged extension
	// using the original MAC as initial values for SHA-1
	sha1_secret_prefix_mac_forge(s4c5_msg_mac_forged, forge_complete, forged_ext_len+ext_pad_len, s4c5_msg_mac);

	free(forge_complete);

	printf("[s4c5] forged_mac = ");
	for(j=0; j<5; j++) {
		printf("%08x", s4c5_msg_mac_forged[j]);
	}
	printf("\n");

	// generate string that leads to forged MAC
	// here we need to guess keylength for correct glue padding
	// brute force keylength up to 1024:
	for(i=0; i<1024; i++) {
		// generate glue padding
		pad_len = sha1_generate_padding(pad, s4c5_msg_len+i);

		// generate string
// 		printf("[s4c5] forge_str_len = %d ?= 123\n", forge_str_len);
		forge_str_len = s4c5_msg_len + pad_len + forged_ext_len;
		forge_str = (unsigned char *) malloc(forge_str_len*sizeof(unsigned char));

		memcpy(forge_str, s4c5_msg, s4c5_msg_len*sizeof(unsigned char));
		memcpy(forge_str+s4c5_msg_len, pad, pad_len*sizeof(unsigned char));
		memcpy(forge_str+s4c5_msg_len+pad_len, forged_ext, forged_ext_len*sizeof(unsigned char));

// 		printf("[s4c5] forge_str = ");
// 		for(j=0; j<forge_str_len; j++) {
// 			printf("%02x", forge_str[j]);
// 		}
// 		printf("\n");

		if(sha1_secret_prefix_mac_auth(s4c5_msg_mac_forged, forge_str, forge_str_len, "YELLOW SUBMARINE!", 17) == 0) {
			printf("[s4c5] MAC for extendend message SUCCESSFULLY forged! Keylength = %d\n", i);
			break;
			free(forge_str);
		}
		free(forge_str);
	}
	
	/**  Set 4 Challenge 6  **/
	/** MD4 KEYED MAC ATTAX **/
	unsigned char s4c6_md4_test[16];
	md4_secret_prefix_mac(s4c6_md4_test, "Hello World!", 12, "YELLOW SUBMARINE", 16);
	printf("[s4c6] test_mac = ");
	for(i=0; i<16; i++) {
		printf("%02x", s4c6_md4_test[i]);
	}
	printf("\n");

	if(md4_secret_prefix_mac_auth(s4c6_md4_test, "Hello World!", 12, "YELLOW SUBMARINE", 16) == 0)
		printf("[s4c6] md4 secret MAC successfully authenticated!\n");
	else
		printf("[s4c6] md4 secret MAC *NOT* authenticated!\n");

	unsigned char s4c6_orig_mac[16];
	unsigned char s4c6_forged_mac[16];

	// calc orig MAC
	md4_secret_prefix_mac(s4c6_orig_mac, s4c5_msg, s4c5_msg_len, "YELLOW SUBMARINE", 16);
	printf("[s4c6] orig_mac = ");
	for(i=0; i<16; i++) {
		printf("%02x", s4c6_orig_mac[i]);
	}
	printf("\n");

	//              MSG LEN      +  PAD_LEN                   +  EXTENSION
	forge_str_len = s4c5_msg_len + (64 - (s4c5_msg_len % 64)) + forged_ext_len;
// 	printf("[s4c5] forge_str_len = %d\n", forge_str_len);
	
	// generate extension padding
	ext_pad_len = md4_generate_padding(ext_pad, forge_str_len);

	forge_complete = malloc((forged_ext_len+ext_pad_len)*sizeof(unsigned char));
	memcpy(forge_complete, forged_ext, forged_ext_len*sizeof(unsigned char));
	memcpy(forge_complete+forged_ext_len, ext_pad, ext_pad_len*sizeof(unsigned char));

	// calc MAC for message with forged extension
	// using the original MAC as initial values for SHA-1
	md4_secret_prefix_mac_forge(s4c6_forged_mac, forge_complete, forged_ext_len+ext_pad_len, s4c6_orig_mac);

	free(forge_complete);

	printf("[s4c6] forged_mac = ");
	for(j=0; j<16; j++) {
		printf("%02x", s4c6_forged_mac[j]);
	}
	printf("\n");

	// generate string that leads to forged MAC
	// here we need to guess keylength for correct glue padding
	// brute force keylength up to 1024:
	for(i=0; i<1024; i++) {
		// generate glue padding
		pad_len = md4_generate_padding(pad, s4c5_msg_len+i);

		// generate string
// 		printf("[s4c5] forge_str_len = %d ?= 123\n", forge_str_len);
		forge_str_len = s4c5_msg_len + pad_len + forged_ext_len;
		forge_str = (unsigned char *) malloc(forge_str_len*sizeof(unsigned char));

		memcpy(forge_str, s4c5_msg, s4c5_msg_len*sizeof(unsigned char));
		memcpy(forge_str+s4c5_msg_len, pad, pad_len*sizeof(unsigned char));
		memcpy(forge_str+s4c5_msg_len+pad_len, forged_ext, forged_ext_len*sizeof(unsigned char));

// 		printf("[s4c5] forge_str = ");
// 		for(j=0; j<forge_str_len; j++) {
// 			printf("%02x", forge_str[j]);
// 		}
// 		printf("\n");

		if(md4_secret_prefix_mac_auth(s4c6_forged_mac, forge_str, forge_str_len, "YELLOW SUBMARINE", 16) == 0) {
			printf("[s4c6] MAC for extendend message SUCCESSFULLY forged! Keylength = %d\n", i);
			break;
			free(forge_str);
		}
		free(forge_str);
	}
	
	/**    Set 4 Challenge 7    **/
	/** SHA1-HMAC TIMING ATTACK **/
	int resp_len=0;
	unsigned char resp[2048];

	// complete param:
	// param0 | filename | param1 | signature | param2
	unsigned char *param0 = "files?utf8=%E2%9C%93&file%5Bfilename%5D=";
	unsigned int param0_len = strlen(param0);
	unsigned char *param1 = "&file%5Bsignature%5D=";
	unsigned int param1_len = strlen(param1);
	unsigned char *param2 = "&commit=Save+File";
	unsigned int param2_len = strlen(param2);

	unsigned char *filename = "report.pdf";
	unsigned int filename_len = strlen(filename);

	unsigned char hmac[20];
	unsigned char hmac_str[40];

	unsigned int req_len = param0_len+filename_len+param1_len+40+param2_len+1;
	unsigned char req[req_len];

	printf("[s4c7/8] Connecting to server...\n");
	memset(hmac, 0, 20*sizeof(unsigned char));

	unsigned int error=0;
	unsigned int k;
	unsigned long resp_time=0;
	unsigned long avg_resp_time=17000;
	// tune this parameter according to the server response
	// times (* not working reliably)
	//        server    |
	//    compare delay | base_time
	//    --------------+----------
	//         50 ms    |   100000
	//         40 ms    |    81000
	//    *    30 ms    |    63000
	//    *    20 ms    |    45000
	//    *    10 ms    |    28000
	// unsigned int base_time = 81000;
	unsigned long base_time = 17000;
	unsigned long run_avg[256];
	double run_var[256];
	unsigned long resp_arr[20];
	unsigned long cmp_time=16000;
	unsigned long cnt=1;
	unsigned int meas_num=20;
	unsigned int lin_coeff = 200;

	// iterate over HMAC bytes
// 	for(i=0; i<1; i++) {
	for(i=0; i<20; i++) {
// 		cmp_time = (cnt > 1) ? (cmp_time*(cnt-1)+resp_time)/cnt: cmp_time + 0.7*resp_time;
// 		cnt++;
		// brute force byte
		for(j=0; j<256; j++) {
			// 'calc' HMAC
			hmac[i] = j;

			for(k=0; k<20; k++)
				sprintf(hmac_str+2*k, "%02x", hmac[k]);
			hmac_str[40] = 0;

			// build request string
			memset(req, 0, req_len*sizeof(unsigned char));
			memcpy(req, param0, param0_len*sizeof(unsigned char));
			memcpy(req+param0_len, filename, filename_len*sizeof(unsigned char));
			memcpy(req+param0_len+filename_len, param1, param1_len*sizeof(unsigned char));
			memcpy(req+param0_len+filename_len+param1_len, hmac_str, 40*sizeof(unsigned char));
			memcpy(req+param0_len+filename_len+param1_len+40, param2, param2_len*sizeof(unsigned char));

			struct timeval tstart;
			struct timeval tstop;
			struct timeval tdiff;
			run_avg[j] = 0;

			for(k=0; k<meas_num; k++) {
				// start timer
				gettimeofday(&tstart, NULL);
				resp_len = http_request(resp, "localhost", 3000, req);
				// stop timer
				gettimeofday(&tstop, NULL);

				timersub(&tstop, &tstart, &tdiff);
				resp_time = (tdiff.tv_sec * (uint64_t)1000000) + tdiff.tv_usec;
				resp_arr[k] = resp_time;

				run_avg[j] += resp_time;
// 				usleep(500);
			}

			resp_time = run_avg[j] / meas_num;

			run_var[j] = 0;
			for(k=0; k<meas_num; k++) {
				run_var[j] += (resp_arr[k] - resp_time) * (resp_arr[k] - resp_time);
			}
			run_var[j] = sqrt((double) run_var[j] / meas_num);

			if(j==0)
				avg_resp_time = resp_time;
			else
				avg_resp_time = (avg_resp_time * j + resp_time)/(j+1);

// 			usleep(500);
// 			printf("[s4c7/8] Avg. Response time: %8d us >? %d (%s)\n", resp_time, base_time, hmac_str);
// 			printf("[s4c7/8] Response time: %2d s %8d us >? %d (%s)\n", tdiff.tv_sec, tdiff.tv_usec, base_time, hmac_str);
// 			cmp_time = (i+1)*base_time - 400*i*i - 4500*i; // + 200*(i-4);
			cmp_time = avg_resp_time + lin_coeff*i + 4000;

// 			printf("[s4c7/8] Avg. Response time: %8d us >? %6d us (%s)\n", resp_time, cmp_time, hmac_str);
			if(resp_time > cmp_time) {
				if((resp_time - cmp_time) < 300)
					lin_coeff -= 20;
				printf("[s4c7/8] Avg. Response time: %8d us >? %6d us (%s)\n", resp_time, cmp_time, hmac_str);
// 				printf("[s4c7/8] Response time: %2d s %8d us (%s)\n", tdiff.tv_sec, tdiff.tv_usec, hmac_str);
				break;
			}

			if(resp_len < 0) {
				printf("[s4c7/8] Connection failed! You started webrick in 'set4/filesrv/', right?\n[s4c7/8] No? Then do so:\n[s4c7/8] $ cd filesrv/\n[s4c7/8] $ bin/rails server\n[s4c7/8] Now try again...\n");
				error=1;
				break;
			}
		}

// 		unsigned int byte = 0;
// 		unsigned int max_resp_time = run_avg[0] / meas_num;
// 		unsigned long var_avg = 0;
// 		for(j=0; j<256; j++) {
// 			var_avg += run_var[j];
// 		}
// 		var_avg = var_avg / 256;
// 		var_avg = 1.1*var_avg;
// 
// 		for(j=0; j<256; j++) {
// 			printf("[s4c7/8] %02x: avg=%8d var=%8f (%s, %6d)\n", j, run_avg[j], run_var[j], (run_var[j]<=var_avg)?"y":"n", var_avg);
// 			if((run_avg[j]/meas_num) > max_resp_time) {
// 				if(run_var[j] <= var_avg) {
// 					max_resp_time = run_avg[j]/meas_num;
// 					byte = j;
// 				}
// 			}
// 		}

// 		hmac[i] = byte;
// 		printf("[s4c7/8] Avg. Response time: %8d us (%02x)\n", max_resp_time, hmac[i]);
// 		cmp_time += 0.7 * resp_time;

		if(error==1)
			break;
	}

	// perform final check
	resp_len = http_request(resp, "localhost", 3000, req);

	// 92 4d 16 7e b3 b7 28 10 e3 1d cc 9e 4f 3c 59 91 73 8e 73 91
	if(resp_len >= 0) {
		resp[resp_len] = 0;
		if(strstr(resp, "+200")!=NULL)
			printf("[s4c7/8] server response: +200! SHA1-HMAC successfully cracked!\n[s4c7/8] SHA1-HMAC: %s\n", hmac_str);
		else
			printf("[s4c7/8] server response: +500! Sorry, SHA1-HMAC cracking attempt failed!\n");
	} else {
		printf("[s4c7/8] Connection failed! You started webrick in 'set4/filesrv/', right?\n[s4c7/8] No? Then do so:\n[s4c7/8] $ cd filesrv/\n[s4c7/8] $ bin/rails server\n[s4c7/8] Now try again...\n");
	}

	return 0;
}

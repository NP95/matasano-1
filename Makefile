all:
	gcc -ggdb -lcrypto hex2base64.c hex_coder.c xor.c histogram.c hamming.c main.c -o main.out

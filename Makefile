all: set1

set1: set1/main.out
	gcc -ggdb -lcrypto src/hex2base64.c src/hex_coder.c src/xor.c src/histogram.c src/hamming.c set1/main.c -o set1/main.out

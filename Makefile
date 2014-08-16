all: set1 set2

set1: set1/main.out
	gcc -ggdb -lcrypto src/hex2base64.c src/hex_coder.c src/xor.c src/histogram.c src/hamming.c set1/main.c -o set1/main.out

set2:  set2/main.out
	gcc -ggdb -lcrypto src/hex_coder.c src/pkcs.c set2/main.c -o set2/main.out

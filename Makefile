all: set1 set2 set3 set4

set1: src/aes.o src/pkcs.o src/hex2base64.o src/hex_coder.o src/xor.o src/histogram.o src/hamming.o set1/main.o
	gcc -ggdb src/aes.c src/pkcs.o src/hex2base64.c src/hex_coder.c src/xor.c src/histogram.c src/hamming.c set1/main.c -lm -lcrypto -o set1/main.out

set2:  src/aes.o src/get.o src/hamming.o src/histogram.o src/hex2base64.o src/xor.o src/hex_coder.o src/pkcs.o set2/main.o
	gcc -ggdb src/get.c src/hamming.c src/histogram.c src/hex2base64.c src/xor.c src/aes.c src/hex_coder.c src/pkcs.c set2/main.c -lm -lcrypto -o set2/main.out

set3:  src/aes.o src/histogram.o src/hamming.o src/hex2base64.o src/xor.o src/hex_coder.o src/pkcs.o src/rrand.o set3/main.o
	gcc -ggdb src/histogram.c src/hamming.c src/hex2base64.c src/xor.c src/aes.c src/hex_coder.c src/pkcs.c src/rrand.c set3/main.c -lm -lcrypto -o set3/main.out

set4:  src/httpget.o src/md4.o src/sha1.o src/mac.o src/aes.o src/histogram.o src/hamming.o src/hex2base64.o src/xor.o src/hex_coder.o src/pkcs.o src/rrand.o set4/main.o
	gcc -ggdb src/httpget.c src/md4.c src/sha1.c src/mac.c src/histogram.c src/hamming.c src/hex2base64.c src/xor.c src/aes.c src/hex_coder.c src/pkcs.c src/rrand.c set4/main.c -lm -lcrypto -o set4/main.out

set5:  src/rmath.o src/dh.o set5/main.o
	gcc -ggdb -fno-stack-protector src/rmath.c src/dh.c set5/main.c -lm -lcrypto -o set5/main.out

clean:
	rm -rf ./src/*.o
	rm -rf ./set*/*.o
	rm -rf ./set*/*.out

linecount:
	wc -l ./set*/*.c ./set*/*.h ./include/*.h ./src/*.c

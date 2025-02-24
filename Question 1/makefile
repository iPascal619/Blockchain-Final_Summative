CC=gcc
CFLAGS=-Wall -Wextra -I"C:\Program Files\OpenSSL-Win64\include"
LDFLAGS=-L"C:\Program Files\OpenSSL-Win64\lib" -lssl -lcrypto

all: job_directory

job_directory: main.c blockchain.c blockchain.h
	$(CC) $(CFLAGS) -o job_directory main.c blockchain.c $(LDFLAGS)

clean:
	rm -f job_directory

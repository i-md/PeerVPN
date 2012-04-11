CC=gcc 
CFLAGS=-Os
LDFLAGS=-lcrypto

all: peervpn
peervpn: peervpn.o

clean:
	rm -f peervpn peervpn.o

CFLAGS+=-O2
LDFLAGS+=-lcrypto -lz

all: peervpn
peervpn: peervpn.o
peervpn.o: peervpn.c

clean:
	rm -f peervpn peervpn.o

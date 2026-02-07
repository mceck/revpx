CFLAGS=-Wall -Wextra -O2 $(shell pkg-config --cflags openssl)
LDFLAGS=$(shell pkg-config --libs openssl)
SRV_CFLAGS=-Wall -Wextra -O2 $(shell pkg-config --cflags openssl yaml-0.1)
SRV_LDFLAGS=$(shell pkg-config --libs openssl yaml-0.1)

all: revpx revpx_lib

build/revpx.o: src/revpx-lib.c src/revpx.h
	$(CC) $(CFLAGS) -c src/revpx-lib.c -o build/revpx.o
	
build/librevpx.so: src/revpx-lib.c src/revpx.h
	$(CC) $(CFLAGS) -shared src/revpx-lib.c -o build/librevpx.so -fPIC $(LDFLAGS)

revpx_lib: build/revpx.o build/librevpx.so

build/revpx: src/revpx-srv.c src/revpx.h
	$(CC) $(SRV_CFLAGS) -o build/revpx src/revpx-srv.c $(SRV_LDFLAGS)

revpx: build/revpx

rust:
	cargo build --release

test: revpx
	scripts/run-tests.sh

example: revpx
	mkcert test.localhost && build/revpx test.localhost 8080 test.localhost.pem test.localhost-key.pem

install: revpx
	sudo install -m 755 build/revpx /usr/local/bin/revpx
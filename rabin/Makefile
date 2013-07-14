CFLAGS+=-g
CFLAGS+=-Wall

all: server client revres tneilc

client: client.o \
	rabin.o \
	rconf.o \
	blk.o \
	win.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

server: server.o \
	parse.o \
	blk.o \
	dpth.o \
	handy.o \
	prepend.o \
	hash.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

revres: revres.o \
	handy.o \
	prepend.o \
	parse.o \
	dpth.o \
	hash.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

tneilc: tneilc.o \
	dpth.o \
	hash.o \
	parse.o \
	prepend.o \
	handy.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

clean:
	rm -f client
	rm -f server
	rm -f revres
	rm -f tneilc
	rm -f *.o


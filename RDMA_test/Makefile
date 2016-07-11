CC=gcc
CFLAGS=-g -O0
LDLIBS=-lrdmacm -libverbs -pthread
BINS= server client

server:accurate_server.o
	$(CC) -o "$@" "$<" $(LDLIBS)

client:accurate_client.o
	$(CC) -o "$@" "$<" $(LDLIBS)

all: $(BIN)

clean:
	rm -rf *.o $(BINS)

.PHONY: server client clean

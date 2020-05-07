CC=g++
LIB=-lnfnetlink -lnetfilter_queue -lpthread
all: nat
nat: mynat.c checksum.c
	${CC} mynat.c checksum.c -o nat ${LIB}
clean:
	rm nat 

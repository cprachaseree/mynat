CC=g++
LIB=-lnfnetlink -lnetfilter_queue -lpthread
all: nat
nat:
	${CC} mynat.c -o nat ${LIB}
clean:
	rm nat 

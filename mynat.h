#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h> 
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>


extern "C" {
	#include <linux/netfilter.h>     /* Defines verdicts (NF_ACCEPT, etc) */
	#include <libnetfilter_queue/libnetfilter_queue.h>
}

struct nat {
	char *internal_ip;
	int internal_port;
	int translated_port;
	time_t timestamp;
};


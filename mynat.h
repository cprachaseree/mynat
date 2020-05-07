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

#define PORT_RANGE 2000

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


struct buffer {
	int end;
	nfq_data **packets;
};

/*
struct buffer_entry {
	struct nat *nat_entry;
	int in_out_bound;
	nfq_data *packets;
};

struct buffer {
	int end;
	struct buffer_entry entries[10];
};
*/

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
#include <unistd.h>

#define PORT_RANGE 2000
#define BUF_LEN 10

extern "C" {
	#include <linux/netfilter.h>     /* Defines verdicts (NF_ACCEPT, etc) */
	#include <libnetfilter_queue/libnetfilter_queue.h>
}

struct nat {
	uint32_t internal_ip;
	uint16_t internal_port;
	uint16_t translated_port;
	time_t timestamp;
};

struct buffer_entry {
	int is_outbound;
	unsigned int id;
	unsigned char *packet;
};

struct buffer {
	int end;
	struct buffer_entry entries[BUF_LEN];
};


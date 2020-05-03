#include "mynat.h"

// Arguments from argv
int IP;
int LAN;
int MASK;
int BUCKET_SIZE;
int FILL_RATE;


// NAT table has to be used in both threads
struct nat *nat_entries;

void get_args(int argc, char **argv);
void invalid_args();
int check_inbound_or_outbound(int source_ip);


/*
 * Callback function installed to netfilter queue
 */
static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData) {
	unsigned int id = 0;
	nfqnl_msg_packet_hdr *header;

	printf("pkt recvd: ");
	if ((header = nfq_get_msg_packet_hdr(pkt))) {
		id = ntohl(header->packet_id);
		printf("  id: %u\n", id);
		printf("  hw_protocol: %u\n", ntohs(header->hw_protocol));		
		printf("  hook: %u\n", header->hook);
	}

	// print the timestamp (PC: seems the timestamp is not always set)
	struct timeval tv;
	if (!nfq_get_timestamp(pkt, &tv)) {
		printf("  timestamp: %lu.%lu\n", tv.tv_sec, tv.tv_usec);
	} else {
		printf("  timestamp: nil\n");
	}

	// Print the payload; in copy meta mode, only headers will be
	// included; in copy packet mode, whole packet will be returned.
	printf(" payload: ");
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (unsigned char**)&pktData);
	if (len > 0) {
		for (int i=0; i<len; ++i) {
			printf("%02x ", pktData[i]);
		}
	}
	printf("\n");
	
	// get ip info from payload
	struct iphdr *ipHeader = (struct iphdr *) pktData;
	printf("Source IP: %u\n", ipHeader->saddr);
	printf("Destination IP: %u\n", ipHeader->daddr);
	printf("Protocol: %d\n", ipHeader->protocol);
	printf("Checksum: %d\n", ipHeader->check);
	printf("\n");
	// get port number from udp header
	struct udphdr *udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
	printf("Source port: %u\n", udpHeader->source);
	printf("Destination port: %u\n", udpHeader->dest);
	printf("Checksum: %u\n", udpHeader->check);

	// add a newline at the end
	printf("\n");

	if (check_inbound_or_outbound(ntohl(ipHeader->saddr)) == 0) {
		// outbound
		printf("Outbound packet\n");
	} else {
		// inbound
		printf("Inbound packet\n");
	}

	// need to check if have token before accepting


	// For this program we'll always accept the packet...
	return nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);

	// end Callback
}

/*
 * Main program
 */
int main(int argc, char **argv) {
	// for our VM A its sudo ./nat 10.3.1.26 10.0.26.0 24 <bucket_size> <fill_rate>
	get_args(argc, argv);

	struct nfq_handle *nfqHandle;

	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[4096];

	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open())) {
		fprintf(stderr, "Error in nfq_open()\n");
		exit(-1);
	}

	// Unbind the handler from processing any IP packets 
	// (seems to be a must)
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_bind_pf()\n");
		exit(1);
	}


	// Install a callback on queue 0
	if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
		fprintf(stderr, "Error in nfq_create_queue()\n");
		exit(1);
	}

	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		// I am not totally sure why a callback mechanism is used
		// rather than just handling it directly here, but that
		// seems to be the convention...
		nfq_handle_packet(nfqHandle, buf, res);
		// end while receiving traffic
	}

	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;
}

void invalid_args() {
	printf("Invalid arguments.\n");
	printf("Usage: sudo ./nat <IP> <LAN> <MASK> <BUCKET_SIZE> <FILL_RATE>\n");
	exit(0);
}

void get_args(int argc, char **argv) {
	if (argc != 6) {
		invalid_args();
	}
	struct in_addr addr;
	if (inet_aton(argv[1], &addr) != 1) {
		printf("Error at ip address argument.\n");
		invalid_args();
	}
	IP = addr.s_addr;
	if (inet_aton(argv[2], &addr) != 1) {
		printf("Error at LAN argument\n");
		invalid_args();
	}
	LAN = addr.s_addr;
	char *c;
	long l;
	l = strtol(argv[3], &c, 10);
	if (*c != '\0' || errno == ERANGE) {
		printf("Error in mask argument\n");
		invalid_args();
	}
	MASK = (int) l;
	if (MASK < 0 || MASK > 32) {
		printf("Invalid mask.");
		invalid_args();
	}
	l = strtol(argv[4], &c, 10);
	if (*c != '\0' || errno == ERANGE) {
		printf("Error in bucket size argument\n");
	}
	BUCKET_SIZE = (int) l;
	l = strtol(argv[5], &c, 10);
    if (*c != '\0' || errno == ERANGE) {
        printf("Error in fill rate argument\n");
    }
	FILL_RATE = (int) l;
	printf("Arguments: \n");
	printf("IP: %d\n", IP);
	printf("LAN: %d\n", LAN);
	printf("MASK: %d\n", MASK);
	printf("BUCKET_SIZE: %d\n", BUCKET_SIZE);
	printf("FILL_RATE: %d\n", FILL_RATE);
	printf("\n");
}

// returns 1 if inbound returns 0 if outbound
// is wrong todo
int check_inbound_or_outbound(int source_ip) {
	unsigned int local_mask = 0xffffffff << (32 - MASK);
	unsigned int local_network = IP & MASK;
	if ((source_ip & local_mask) == local_network) {
		return 0;
	} else {
		return 1;
	}	
}

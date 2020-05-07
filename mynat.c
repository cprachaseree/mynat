#include "mynat.h"
#include "checksum.h"

// Arguments from argv
int IP;
int LAN;
int MASK;
int BUCKET_SIZE;
int FILL_RATE;

// nfq as global variable
struct nfq_handle *nfqHandle;
struct nfq_q_handle *myQueue;

// NAT table has to be used in both threads
struct nat *nat_entries;
// user space buffer used in both threads
struct buffer buf;

pthread_mutex_t nat_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t userbuffer_lock = PTHREAD_MUTEX_INITIALIZER;


void get_args(int argc, char **argv);
void invalid_args();
int check_inbound_or_outbound(int source_ip);
void *read_packets(void *args);
void *process_packets(void *args);
static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData);
void init_buffer();
void init_nfqueue();
void process_inbound_packets(nfq_data* packet);
void process_outbound_packets(nfq_data* packet);



/*
 * Main program
 */
int main(int argc, char **argv) {
	// for our VM A its sudo ./nat 10.3.1.26 10.0.26.0 24 <bucket_size> <fill_rate>
	get_args(argc, argv);
	// IP and LAN is in network byte order. BUCKET_SIZE and FILL_RATE is int

	// set buffer size to 10 and end to -1
	init_buffer();
	
	// set nfqueue handler
	init_nfqueue();

	// create threads
	pthread_t threads[2];
	if ((pthread_create(&threads[0], NULL, read_packets, NULL) != 0) ||
		(pthread_create(&threads[1], NULL, process_packets, NULL))) {
		printf("Error creating thread.");
	}
	if ((pthread_join(threads[0], NULL) != 0) ||
		(pthread_join(threads[1], NULL)) != 0) {
		printf("Error joining thread.");
	}

	nfq_destroy_queue(myQueue);
	nfq_close(nfqHandle);
	
	return 0;
}

void *process_packets(void *args) {
	int i, destination_port, is_outbound;
	nfq_data *packet;
	struct iphdr *ipHeader;
	struct udphdr *udpHeader;
	unsigned int id;
	nfqnl_msg_packet_hdr *header;

	while (1) {
		pthread_mutex_lock(&userbuffer_lock);
		if (buf.end == -1) {
			continue;
			pthread_mutex_unlock(&userbuffer_lock);
		}
		packet = buf.packets[0];
		pthread_mutex_unlock(&userbuffer_lock);
		if ((header = nfq_get_msg_packet_hdr(packet))) {
			id = ntohl(header->packet_id);
			printf("  id: %u\n", id);
			printf("  hw_protocol: %u\n", ntohs(header->hw_protocol));		
			printf("  hook: %u\n", header->hook);
		}
		// get ip info of packet
		ipHeader = (struct iphdr *) packet;
		printf("Received Source IP: %u\n", ntohl(ipHeader->saddr));
		printf("Received Destination IP: %u\n", ntohl(ipHeader->daddr));
		printf("Received IP Checksum: %d\n", ntohl(ipHeader->check));
		printf("\n");
			
		// get port number from udp header
		udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
		printf("Received Source port: %u\n", udpHeader->source);
		printf("Received Destination port: %u\n", udpHeader->dest);
		printf("Received UDP Checksum: %u\n", udpHeader->check);

		is_outbound = check_inbound_or_outbound(ntohl(ipHeader->saddr));
		if (is_outbound == 0) {
			process_inbound_packets(packet);
		} else if (is_outbound == 1) {
			process_outbound_packets(packet);
		}

		// send out packet by waiting for tokens

		// move up the queue
		pthread_mutex_lock(&userbuffer_lock);
		for (i = 1; i < buf.end; i++) {
			buf.packets[i-1] = buf.packets[i];
		}
		buf.packets[buf.end] = NULL;
		buf.end--;
		pthread_mutex_unlock(&userbuffer_lock);
		// blocking wait for token

		// set verdict
		nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);
	}
	pthread_exit(NULL);
}

void process_inbound_packets(nfq_data* packet) {
	int i;
	struct iphdr *ipHeader;
	struct udphdr *udpHeader;
	unsigned int ip_in_nat, destination_ip, source_port, destination_port, 
		trans_port;
	struct in_addr addr;

	ipHeader = (struct iphdr *) packet;
	destination_ip = ntohl(ipHeader->daddr);
	printf("Received Destination IP: %u\n", destination_ip);
	printf("\n");
			
	// get port number from udp header
	udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
	source_port = ntohl(udpHeader->source);
	destination_port = ntohl(udpHeader->dest);
	printf("Destination port: %d", destination_port);
	
	for (i = 0; i < 2000; i++) {
		trans_port = nat_entries[i].translated_port;
		if (trans_port == destination_port) {
			printf("translated_port %d\n", trans_port);
			break;
		}  
	}
	if (i == 2000) {
		printf("Packet does not exist in NAT table.");
		return;
	}
	// change source port
	udpHeader->dest = nat_entries[i].internal_port;
	udpHeader->check = udp_checksum((unsigned char *) packet);

	if (inet_aton(nat_entries[i].internal_ip, &addr) != 1) {
		printf("Error at ip address argument.\n");
		invalid_args();
	}
	// destination IP unchanged
	ipHeader->daddr = addr.s_addr;
	ipHeader->check = ip_checksum((unsigned char *) packet);
}

void process_outbound_packets(nfq_data* packet) {
	int i;
	struct iphdr *ipHeader;
	struct udphdr *udpHeader;
	unsigned int ip_in_nat, source_ip, source_port, destination_port;
	struct in_addr addr;

	ipHeader = (struct iphdr *) packet;
	source_ip = ntohl(ipHeader->saddr);
	printf("Received Source IP: %u\n", source_ip);
	printf("\n");
			
	// get port number from udp header
	udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
	source_port = ntohl(udpHeader->source);
	destination_port = ntohl(udpHeader->dest);
	printf("Source port: %d", source_port);
	
	for (i = 0; i < 2000; i++) {
		if (inet_aton(nat_entries[i].internal_ip, &addr) != 1) {
			printf("Error at ip address argument.\n");
			invalid_args();
		}
		if (ntohl(addr.s_addr) == source_ip) {
			break;
		}  
	}
	if (i == 2000) {
		printf("Packet does not exist in NAT table.");
		return;
	}
	// change source port
	udpHeader->source = nat_entries[i].translated_port;
	udpHeader->check = udp_checksum((unsigned char *) packet);

	// destination IP unchanged
	ipHeader->saddr = IP;
	ipHeader->check = ip_checksum((unsigned char *) packet);
}

void *read_packets(void *args) {
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[4096];
	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		nfq_handle_packet(nfqHandle, buf, res);
	}
	
	pthread_exit(NULL);
}

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
	printf("Source IP: %u\n", ntohl(ipHeader->saddr));
	printf("Destination IP: %u\n", ntohl(ipHeader->daddr));
	printf("Protocol: %d\n", ntohl(ipHeader->protocol));
	printf("Checksum: %d\n", ntohl(ipHeader->check));
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
int check_inbound_or_outbound(int source_ip) {
	printf("Source ip: %u\n", source_ip); // 10.0.26.2 for vm b
	printf("Internal ip: %u\n", ntohl(LAN)); //  10.0.26.1                 
	unsigned int local_mask = 0xffffffff << (32 - MASK); 
	printf("Local mask: %u\n", local_mask); // 255.255.255.0
	unsigned int local_network = ntohl(LAN) & local_mask;
	printf("Local Network: %u\n", local_network); // 10.0.26.0
	printf("source_ip & local_mask: %u\n", (source_ip & local_mask));
	if ((source_ip & local_mask) == local_network) {
		return 0;
	} else {
		return 1;
	}	
}

void init_buffer() {
	buf.end = -1;
	buf.packets = (nfq_data **) calloc(10, sizeof(nfq_data *));
}

void init_nfqueue() {
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
}

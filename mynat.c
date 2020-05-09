#include "mynat.h"
#include "checksum.h"

// Arguments from argv
uint32_t IP;
uint32_t LAN;
int MASK;
int BUCKET_SIZE;
int FILL_RATE;

int tokens;

// nfq as global variable
struct nfq_handle *nfqHandle;
struct nfq_q_handle *myQueue;

// NAT table has to be used in both threads
struct nat nat_entries[PORT_RANGE];
// user space buffer used in both threads
struct buffer buf;

pthread_mutex_t nat_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t userbuffer_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t tokens_lock = PTHREAD_MUTEX_INITIALIZER;

void get_args(int argc, char **argv);
void invalid_args();
int check_inbound_or_outbound(uint32_t source_ip);
void *read_packets(void *args);
void *process_packets(void *args);
void *release_tokens(void *args);
static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData);
void init_buffer();
void init_nfqueue();
void process_inbound_packets(unsigned char *packet);
void process_outbound_packets(unsigned char *packet);
void init_nat_table();
void remove_expired_nat();
struct nat* inbound_nat_search(uint16_t port);
struct nat* outbound_nat_search(uint32_t ip, uint16_t port);
struct nat* create_nat_entry(uint32_t internal_ip, int internal_port);
void print_nat_table();

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

	// set all internal ip in nat table to NULL
	init_nat_table();

	// create threads
	pthread_t threads[2], token_thread;
	if (pthread_create(&threads[0], NULL, read_packets, NULL) != 0 ||
		pthread_create(&threads[1], NULL, process_packets, NULL) != 0 ||
		pthread_create(&token_thread, NULL, release_tokens, NULL) != 0) {
		printf("Error creating thread.");
	}
	if (pthread_join(threads[0], NULL) != 0 ||
		pthread_join(threads[1], NULL) != 0 ||
	    pthread_join(token_thread, NULL) != 0) {
		printf("Error joining thread.");
	}

	nfq_destroy_queue(myQueue);
	nfq_close(nfqHandle);
	
	return 0;
}

void *process_packets(void *args) {
	int i, destination_port;
	struct iphdr *ipHeader;
	struct udphdr *udpHeader;
	unsigned int id;
	nfqnl_msg_packet_hdr *header;
	struct buffer_entry buf_ent;

	while (1) {
		pthread_mutex_lock(&userbuffer_lock);
		if (buf.end == -1) {
			pthread_mutex_unlock(&userbuffer_lock);
			continue;
		}
		buf_ent = buf.entries[0];
		pthread_mutex_unlock(&userbuffer_lock);

		id = buf_ent.id;
		ipHeader = (struct iphdr *) buf_ent.packet;
		printf("Received Source IP: %u\n", ntohl(ipHeader->saddr));
		printf("Received Destination IP: %u\n", ntohl(ipHeader->daddr));
		printf("Received IP Checksum: %d\n", ntohl(ipHeader->check));
		printf("\n");
		fflush(stdout);
			
		// get port number from udp header
		udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
		printf("Received Source port: %u\n", udpHeader->source);
		printf("Received Destination port: %u\n", udpHeader->dest);
		printf("Received UDP Checksum: %u\n", udpHeader->check);
		
		// is_outbound = check_inbound_or_outbound(ntohl(ipHeader->saddr));
		if (buf_ent.is_outbound == 0) {
			process_inbound_packets(buf_ent.packet);
		} else if (buf_ent.is_outbound == 1) {
			process_outbound_packets(buf_ent.packet);
		}

		// send out packet by waiting for tokens

		struct buffer_entry e;
		printf("Before shifting the buffer\n");
		for (int j = 0; j <= buf.end; j++) {
			e = buf.entries[j];
			printf("buffer entry id:\n%d\n", e.id);
			// printf("NAT entries:\n");
			// printf("Internal ip: %d, Internal port: %d, Translated port: %d\n", 
			// 	e.nat_entry->internal_ip, e.nat_entry->internal_port,  e.nat_entry->translated_port);
		}

		// move up the queue
		printf("%d\n", buf.end);
		pthread_mutex_lock(&userbuffer_lock);
		for (i = 1; i <= buf.end; i++) {
			buf.entries[i-1] = buf.entries[i];
		}
		memset(&buf.entries[buf.end], 0, sizeof(struct buffer_entry));
		buf.end--;
		pthread_mutex_unlock(&userbuffer_lock);
		printf("%d\n", buf.end);
		printf("After shifting the buffer\n");
		for (int j = 0; j <= buf.end; j++) {
			e = buf.entries[j];
			printf("buffer entry id:\n%d\n", e.id);
			// printf("NAT entries:\n");
			// printf("Internal ip: %d, Internal port: %d, Translated port: %d\n", 
			// 	e.nat_entry->internal_ip, e.nat_entry->internal_port,  e.nat_entry->translated_port);
		}
		pthread_mutex_lock(&tokens_lock);
		// wait for available token
		while (tokens == 0) {
			pthread_mutex_unlock(&tokens_lock);
		}
		// consume token
		tokens--;
		pthread_mutex_unlock(&tokens_lock);

		// set verdict
		nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);

	}
	pthread_exit(NULL);
}

void process_inbound_packets(unsigned char *packet) {
	struct iphdr *ipHeader;
	struct udphdr *udpHeader;
	unsigned int ip_in_nat, destination_ip, source_port, destination_port, 
		trans_port;
	struct in_addr addr;
	struct nat *nat_entry;

	ipHeader = (struct iphdr *) packet;
	destination_ip = ntohl(ipHeader->daddr);
	printf("Received Destination IP: %u\n", destination_ip);
	printf("\n");
			
	// get port number from udp header
	udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
	source_port = ntohs(udpHeader->source);
	destination_port = ntohs(udpHeader->dest);
	printf("Destination port: %d\n", destination_port);

	nat_entry = inbound_nat_search(destination_port);
	nat_entry->timestamp = time(NULL);
	printf("Entry at port %u found\n", nat_entry->translated_port);
	
	// change dest port
	udpHeader->dest = htons(nat_entry->internal_port);
	udpHeader->check = udp_checksum(packet);

	// destination IP unchanged
	ipHeader->daddr = htonl(nat_entry->internal_ip);
	ipHeader->check = ip_checksum(packet);
}

void process_outbound_packets(unsigned char *packet) {
	struct iphdr *ipHeader;
	struct udphdr *udpHeader;
	unsigned int ip_in_nat, source_ip, source_port, destination_port;
	struct nat *nat_entry;

	ipHeader = (struct iphdr *) packet;
	source_ip = ntohl(ipHeader->saddr);
	printf("Received Source IP: %u\n", source_ip);
	printf("\n");
			
	// get port number from udp header
	udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
	source_port = ntohs(udpHeader->source);
	destination_port = ntohs(udpHeader->dest);
	printf("Source port: %d\n", source_port);

	nat_entry = outbound_nat_search(source_ip, source_port);
	if (nat_entry == NULL) {
		nat_entry = create_nat_entry(source_ip, source_port);
		printf("Created new entry at port %u\n", nat_entry->translated_port);
	}
	else {
		nat_entry->timestamp = time(NULL);
		printf("Entry at port %u found\n", nat_entry->translated_port);
	}

	udpHeader->source = nat_entry->translated_port;
	udpHeader->check = udp_checksum(packet);

	// destination IP unchanged
	ipHeader->saddr = htonl(IP);
	ipHeader->check = ip_checksum(packet);
}

struct nat* inbound_nat_search(uint16_t port) {
	// return the pointer to nat_entries where translated_port is matched to port
	// return NULL if no such entry
	int i;
	for (i = 0; i < PORT_RANGE; i++) {
		if (nat_entries[i].translated_port == port) {
			printf("translated_port %d\n", nat_entries[i].translated_port);
			return &nat_entries[i];
		}  
	}
	if (i == PORT_RANGE) {
		return NULL;
	}
}

struct nat* outbound_nat_search(uint32_t ip, uint16_t port) {
	// return the pointer to the nat_entries where internal_ip is matched to ip 
	// and internal_port is matched to port
	// return -1 if no such entry
	int i;
	for (i = 0; i < PORT_RANGE; i++) {
		if (nat_entries[i].internal_ip == ip &&
			nat_entries[i].internal_port == port)
			return &nat_entries[i];
	}
	if (i == PORT_RANGE) {
		return NULL;
	}
}

void *read_packets(void *args) {
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[1500]; // MTU size
	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	while(1) {
		while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
			nfq_handle_packet(nfqHandle, buf, res);
		}
	}
	pthread_exit(NULL);
}

static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData) {

	unsigned char *pktData;
	unsigned int id;
	nfqnl_msg_packet_hdr *header;
	if ((header = nfq_get_msg_packet_hdr(pkt))) {
		id = ntohl(header->packet_id);
		printf("id: %u\n", id);
	}
	int len = nfq_get_payload(pkt, (unsigned char**)&pktData);

	// get ip info from payload
	struct iphdr *ipHeader = (struct iphdr *) pktData;


	// get port number from udp header
	struct udphdr *udpHeader = (struct udphdr *) (((char *) ipHeader) + ipHeader->ihl*4);
	
	// set internal_ip of expired nat_entries to NULL
	remove_expired_nat();
	
	if (buf.end == BUF_LEN - 1)
		return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);

	int is_outbound = check_inbound_or_outbound(ntohl(ipHeader->saddr));
	struct buffer_entry *buf_ent;
	struct nat *nat_entry;

	nat_entry = inbound_nat_search(ntohs(udpHeader->dest));
	if (nat_entry == NULL) {
		printf("Drop Inbound with no entry\n"); 
		return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
	}
	
	// insert to buffer	
	pthread_mutex_lock(&userbuffer_lock);
	buf.end++;
	buf_ent = &buf.entries[buf.end];
	buf_ent->id = id;
	buf_ent->is_outbound = is_outbound;
	buf_ent->packet = pktData;
	pthread_mutex_unlock(&userbuffer_lock);
	return 0;
}

void print_nat_table() {
	int i;
	struct in_addr addr_in, addr_tran;
	struct nat *entry;
	addr_tran.s_addr = htonl(IP);
	printf(" %s | %s | %s | %s \n", 
	"Internal IP", "Internal Port", "Translated IP", "Translated Port");
	for(i = 0; i < PORT_RANGE; i++) {
		if (nat_entries[i].internal_ip != 0) {
			entry = &nat_entries[i];
			addr_in.s_addr = htonl(entry->internal_ip);
			printf(" %11s | %13u | %13s | %15u \n",
			inet_ntoa(addr_in), entry->internal_port,
			inet_ntoa(addr_tran), entry->translated_port);
		}
	}
}

struct nat* create_nat_entry(uint32_t internal_ip, int internal_port) {
	int i;
	for (i = 0; i < PORT_RANGE; i++) {
		if (nat_entries[i].internal_ip == 0)
			break;	
	}
	struct nat *entry = &nat_entries[i];
	entry->internal_ip = internal_ip;
	entry->internal_port = internal_port;
	entry->translated_port = i + 10000;
	entry->timestamp = time(NULL);
	print_nat_table();
	return entry;
}	
	

void remove_expired_nat() {
	int i;
	time_t now = time(NULL);
	for (i = 0; i < PORT_RANGE; i++) {
		if (nat_entries[i].internal_ip != 0 &&
			(now - nat_entries[i].timestamp) > 10) {
			nat_entries[i].internal_ip = 0;
			print_nat_table();
		}
	}
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
	IP = ntohl(addr.s_addr);
	if (inet_aton(argv[2], &addr) != 1) {
		printf("Error at LAN argument\n");
		invalid_args();
	}
	LAN = ntohl(addr.s_addr);
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
	printf("IP: %u\n", IP);
	printf("LAN: %u\n", LAN);
	printf("MASK: %d\n", MASK);
	printf("BUCKET_SIZE: %d\n", BUCKET_SIZE);
	printf("FILL_RATE: %d\n", FILL_RATE);
	printf("\n");
}

// returns 1 if inbound returns 0 if outbound
int check_inbound_or_outbound(uint32_t source_ip) {
	// printf("Source ip: %u\n", source_ip); // 10.0.26.2 for vm b
	// printf("Internal ip: %u\n", ntohl(LAN)); //  10.0.26.1                 
	unsigned int local_mask = 0xffffffff << (32 - MASK); 
	// printf("Local mask: %u\n", local_mask); // 255.255.255.0
	unsigned int local_network = LAN & local_mask;
	// printf("Local Network: %u\n", local_network); // 10.0.26.0
	// printf("source_ip & local_mask: %u\n", (source_ip & local_mask));
	if ((source_ip & local_mask) == local_network) {
		return 0;
	} else {
		return 1;
	}	
}

void init_buffer() {
	buf.end = -1;
	// buf.packets = (nfq_data **) calloc(10, sizeof(nfq_data *));
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

void init_nat_table() {
	int i;
	for (i = 0; i < PORT_RANGE; i++)
		nat_entries[i].internal_ip = 0;
}

void *release_tokens(void *args) {
	tokens = BUCKET_SIZE;

	while(1) {
		pthread_mutex_lock(&tokens_lock);
		if (tokens + FILL_RATE > BUCKET_SIZE) {
			tokens = BUCKET_SIZE;
		} else {
			tokens += FILL_RATE;
		}
		pthread_mutex_unlock(&tokens_lock);
		sleep(1);
	}
}

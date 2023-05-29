#include <stdio.h>
#include <pcap.h> //Provides declarations for pcap library
#include <stdint.h>
#include <arpa/inet.h> //Provides declarations for inet_ntoa()
#include <string.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <sys/socket.h>	  //Provides declarations for sockets
#include <net/ethernet.h> //Provides declarations for ethernet header
#include <netinet/ip.h>	  //Provides declarations for ip header
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h> //Provides declarations for sockets
#include <netinet/ip.h> //Provides declarations for ip header
#include <unistd.h>
#include <errno.h>

#define FILTER "icmp and src 192.168.1.227"// we want to spoof only the packets that are coming from the host.
// #define FILTER "tcp portrange 9998-9999"
// #define FILTER "tcp dst portrange 10-100"
//#define FILTER "icmp"

void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_icmp_packet(const u_char *, int);
void print_tcp_packet(const u_char *, int, const struct pcap_pkthdr *);
void PrintData(const u_char *, int);
unsigned short in_cksum(unsigned short *, int);

struct sockaddr_in source, dest;
int tcp = 0, others = 0, icmp = 0, total = 0;

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

/* Ethernet Header */
struct ethheader
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type;					/* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader
{
	unsigned char iph_ihl : 4,		 // IP header length
		iph_ver : 4;				 // IP version
	unsigned char iph_tos;			 // Type of service
	unsigned short int iph_len;		 // IP Packet length (data + header)
	unsigned short int iph_ident;	 // Identification
	unsigned short int iph_flag : 3, // Fragmentation flags
		iph_offset : 13;			 // Flags offset
	unsigned char iph_ttl;			 // Time to Live
	unsigned char iph_protocol;		 // Protocol type
	unsigned short int iph_chksum;	 // IP datagram checksum
	struct in_addr iph_sourceip;	 // Source IP address
	struct in_addr iph_destip;		 // Destination IP address
};

/* ICMP Header  */
struct icmpheader
{
	unsigned char icmp_type;		// ICMP message type
	unsigned char icmp_code;		// Error code
	unsigned short int icmp_chksum; // Checksum for ICMP Header and data
	unsigned short int icmp_id;		// Used for identifying request
	unsigned short int icmp_seq;	// Sequence number
};

/* API Header */
struct calculatorPacket
{
	uint32_t unixtime;
	uint16_t length;
	uint16_t reserved : 3,
		c_flag : 1,
		s_flag : 1,
		t_flag : 1,
		status : 10;
	uint16_t cache;
	uint16_t padding;
} cpack, *pcpack;

void send_raw_ip_packet(struct ipheader *ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;

	// Step 1: Create a raw network socket.
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == -1)
	{
		fprintf(stderr, "socket() failed with error: %d", errno);
		fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
		return;
	}

	// Step 2: Set socket option.
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
			   &enable, sizeof(enable));

	// Step 3: Provide needed information about destination.
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	// Step 4: Send the packet out.
	int bytes_sent = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	if (bytes_sent == -1)
	{
		fprintf(stderr, "sendto() failed with error: %d", errno);
		return;
	}

	close(sock);
}

/* Icmp Write Function */
void print_icmp_packet(const u_char *Buffer, int Size)
{
	//////////////////////////* Link; Ethernet Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	//////////////////////////* Network; IP Header *////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct iphdr *iph = (struct iphdr *)(Buffer + 14);
	unsigned short iphdrlen = iph->ihl * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	//printf("src: %s\n", inet_ntoa(source.sin_addr));
	//printf("dst: %s\n", inet_ntoa(dest.sin_addr));

	char buffer[1500];
	memset(buffer, 0, 1500);

	/*********************************************************
	   Step 1: Fill in the ICMP header.
	 ********************************************************/
	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
	icmp->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.
	icmp->icmp_code = 0; // Identifier (16 bits): some number to trace the response.
	icmp->icmp_id = 18;	 // Sequence Number (16 bits): starts at 0
	// Calculate the checksum for integrity
	icmp->icmp_seq = 0;
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

	/*********************************************************
		Step 2: Fill in the IP header.
	  ********************************************************/
	//printf("src: %s\n", inet_ntoa(source.sin_addr));
	//printf("dst: %s\n", inet_ntoa(dest.sin_addr));

	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr(inet_ntoa(dest.sin_addr));
	ip->iph_destip.s_addr = inet_addr(inet_ntoa(source.sin_addr));
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) +
						sizeof(struct icmpheader));
	struct sockaddr_in source2, dest2;
	memset(&source, 0, sizeof(source2));
	source2.sin_addr.s_addr = ip->iph_sourceip.s_addr;
	
	printf("ip src: %s\n", inet_ntoa(source2.sin_addr));

	/*********************************************************
	   Step 3: Finally, send the spoofed packet
	 ********************************************************/
	send_raw_ip_packet(ip);

	return;
}
void print_icmp_packet_any(const u_char *Buffer, int Size)
{
	//////////////////////////* Link; Ethernet Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	//////////////////////////* Network; IP Header *////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct iphdr *iph = (struct iphdr *)(Buffer + 16);
	unsigned short iphdrlen = iph->ihl * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	//printf("src: %s\n", inet_ntoa(source.sin_addr));
	//printf("dst: %s\n", inet_ntoa(dest.sin_addr));

	char buffer[1500];
	memset(buffer, 0, 1500);

	/*********************************************************
	   Step 1: Fill in the ICMP header.
	 ********************************************************/
	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader)+2);
	icmp->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.
	icmp->icmp_code = 0; // Identifier (16 bits): some number to trace the response.
	icmp->icmp_id = 18;	 // Sequence Number (16 bits): starts at 0
	// Calculate the checksum for integrity
	icmp->icmp_seq = 0;
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

	/*********************************************************
		Step 2: Fill in the IP header.
	  ********************************************************/
	//printf("src: %s\n", inet_ntoa(source.sin_addr));
	//printf("dst: %s\n", inet_ntoa(dest.sin_addr));

	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr(inet_ntoa(dest.sin_addr));
	ip->iph_destip.s_addr = inet_addr(inet_ntoa(source.sin_addr));
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) +
						sizeof(struct icmpheader));
	struct sockaddr_in source2, dest2;
	memset(&source, 0, sizeof(source2));
	source2.sin_addr.s_addr = ip->iph_sourceip.s_addr;
	
	printf("ip src: %s\n", inet_ntoa(source2.sin_addr));

	/*********************************************************
	   Step 3: Finally, send the spoofed packet
	 ********************************************************/
	send_raw_ip_packet(ip);

	return;
}

/* Main logfile Function */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int size = header->len;

	// Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
	total++;
	switch (iph->protocol) // Check the Protocol and do accordingly...
	{
	case 0: // ICMP Protocol
		++icmp;
		print_icmp_packet(packet, size);

		break;

	case 1: // ICMP Protocol
		++icmp;
		print_icmp_packet(packet, size);
		break;

	default: // Some Other Protocol like ARP etc.
		++others;
		break;
	}
}
void got_packet_any(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int size = header->len;

	// Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
	total++;
	switch (iph->protocol) // Check the Protocol and do accordingly...
	{
	case 0: // ICMP Protocol
		++icmp;
		print_icmp_packet_any(packet, size);

		break;

	case 1: // ICMP Protocol
		++icmp;
		print_icmp_packet_any(packet, size);
		break;

	default: // Some Other Protocol like ARP etc.
		++others;
		break;
	}
}

// Packet Sniffing using the pcap API
int main()
{
	struct bpf_program fp;
	char filter_exp[] = FILTER; /* The filter expression */
	bpf_u_int32 net;			/* The IP of our sniffing device */
	pcap_if_t *alldevsp, *device;
	pcap_t *handle; // Handle of the device that shall be sniffed
	char errbuf[100], *devname, devs[100][100];
	int count = 1, n;
	// First get the list of available devices
	printf("Finding available devices ... ");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("Error finding devices : %s", errbuf);
		return -1;
	}
	printf("Done");
	// Print the available devices
	printf("\nAvailable Devices are :\n");
	for (device = alldevsp; device != NULL; device = device->next)
	{
		printf("%d. %s - %s\n", count, device->name, device->description);
		if (device->name != NULL)
		{
			strcpy(devs[count], device->name);
		}
		count++;
	}
	// Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d", &n);
	devname = devs[n];
	printf("Device: %s\n", devname);
	//  Step 1: Open live pcap session on NIC
	handle = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s.\n", devname);
		return (2);
	}
	// Step 2: Compile filter_exp into BPF psuedo-code
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't compile filter: %s.\n", filter_exp);
		return (2);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't set filter: %s.\n", filter_exp);
		return (2);
	}
	if(strcmp(devname,"any")==0)
	{
	pcap_loop(handle, -1, got_packet_any, NULL);
	}
	else 
	{
		pcap_loop(handle, -1, got_packet, NULL);
	}
	pcap_close(handle); // Close the handle
	return 0;
}

unsigned short in_cksum(unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	/*
	 * The algorithm uses a 32 bit accumulator (sum), adds
	 * sequential 16 bit words to it, and at the end, folds back all
	 * the carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end, if any */
	if (nleft == 1)
	{
		*(u_char *)(&temp) = *(u_char *)w;
		sum += temp;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);					// add carry
	return (unsigned short)(~sum);
}

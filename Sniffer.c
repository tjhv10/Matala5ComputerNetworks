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

#define FILTER ""
// #define FILTER "tcp portrange 9998-9999"
//#define FILTER "tcp dst portrange 10-100"
//#define FILTER "icmp and host 8.8.8.8 and host 10.0.2.15"

void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_icmp_packet(const u_char *, int);
void print_tcp_packet(const u_char *, int, const struct pcap_pkthdr *);
void PrintData(const u_char *, int);

FILE *logfile;
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
struct icmpheadr
{
	u_int8_t type; /* message type */
	u_int8_t code; /* type sub-code */
	u_int16_t checksum;
	union
	{
		struct
		{
			u_int16_t id;
			u_int16_t sequence;
		} echo;			   /* echo datagram */
		u_int32_t gateway; /* gateway address */
		struct
		{
			u_int16_t __unused;
			u_int16_t mtu;
		} frag; /* path mtu discovery */
	} un;
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

void PrintData(const u_char *data, int Size)
{
	int i, j;
	for (i = 0; i < Size; i++)
	{
		if (i != 0 && i % 16 == 0) // if one line of hex printing is complete...
		{
			fprintf(logfile, "         ");
			for (j = i - 16; j < i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(logfile, "%c", (unsigned char)data[j]); // if its a number or alphabet

				else
					fprintf(logfile, "."); // otherwise print a dot
			}
			fprintf(logfile, "\n");
		}

		if (i % 16 == 0)
			fprintf(logfile, "   ");
		fprintf(logfile, " %02X", (unsigned int)data[i]);

		if (i == Size - 1) // print the last spaces
		{
			for (j = 0; j < 15 - i % 16; j++)
			{
				fprintf(logfile, "   "); // extra spaces
			}

			fprintf(logfile, "         ");

			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
				{
					fprintf(logfile, "%c", (unsigned char)data[j]);
				}
				else
				{
					fprintf(logfile, ".");
				}
			}

			fprintf(logfile, "\n");
		}
	}
}

/* Icmp Write Function */
void print_icmp_packet(const u_char *Buffer, int Size)
{
	fprintf(logfile, "***********************ICMP Packet*************************\n");
	//////////////////////////* Link; Ethernet Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	//////////////////////////* Network; IP Header *////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));

	//////////////////////////* Transport; ICMP Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct icmpheadr *icmph = (struct icmpheadr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	fprintf(logfile, "   |-Type : %u", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile, "  (TTL Expired)\n");
	}
	else if ((unsigned int)(icmph->type) == 0)
	{
		fprintf(logfile, "  (ICMP Echo Reply)\n");
	}
	else if ((unsigned int)(icmph->type) == 8)
	{
		fprintf(logfile, "  (ICMP Echo Request)\n");
	}

	fprintf(logfile, "   |-Code : %u\n", (unsigned short)(icmph->code));
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(icmph->checksum));
	fprintf(logfile, "   |-ID       : %d\n", ntohs(icmph->un.echo.id));
	fprintf(logfile, "   |-Sequence : %d\n", ntohs(icmph->un.echo.sequence));

	///////////////////////////////////* DATA */////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA                         ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "ICMP Header\n");
	PrintData(Buffer + iphdrlen, sizeof icmph);

	fprintf(logfile, "Data Payload\n");

	// Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size, (Size - header_size));
}
void print_icmp_packet_any(const u_char *Buffer, int Size)
{
	fprintf(logfile, "***********************ICMP Packet*************************\n");
	//////////////////////////* Link; Ethernet Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	//////////////////////////* Network; IP Header *////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr)+2);
	unsigned short iphdrlen = iph->ihl * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));

	//////////////////////////* Transport; ICMP Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct icmpheadr *icmph = (struct icmpheadr *)(Buffer + iphdrlen + sizeof(struct ethhdr)+2);
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	fprintf(logfile, "   |-Type : %u", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile, "  (TTL Expired)\n");
	}
	else if ((unsigned int)(icmph->type) == 0)
	{
		fprintf(logfile, "  (ICMP Echo Reply)\n");
	}
	else if ((unsigned int)(icmph->type) == 8)
	{
		fprintf(logfile, "  (ICMP Echo Request)\n");
	}

	fprintf(logfile, "   |-Code : %u\n", (unsigned short)(icmph->code));
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(icmph->checksum));
	fprintf(logfile, "   |-ID       : %d\n", ntohs(icmph->un.echo.id));
	fprintf(logfile, "   |-Sequence : %d\n", ntohs(icmph->un.echo.sequence));

	///////////////////////////////////* DATA */////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA                         ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "ICMP Header\n");
	PrintData(Buffer + iphdrlen, sizeof icmph);

	fprintf(logfile, "Data Payload\n");

	// Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size, (Size - header_size));
}

/* Tcp Write Function */
void print_tcp_packet(const u_char *Buffer, int Size, const struct pcap_pkthdr *header)
{
	fprintf(logfile, "***********************TCP Packet*************************\n");

	//////////////////////////* Link; Ethernet Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	// fprintf(logfile, "Ethernet Header\n");
	// fprintf(logfile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	// fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	// fprintf(logfile, "   |-Protocol            : %u \n", (unsigned short)eth->h_proto);

	//////////////////////////* Network; IP Header *////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	// fprintf(logfile, "\n");
	// fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   |-Packet No.       : %d\n", total);
	// fprintf(logfile, "   |-IP Version        : %d\n", (unsigned int)iph->version);
	// fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	// fprintf(logfile, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	// fprintf(logfile, "   |-IP Total Length  : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	// fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph->id));
	// fprintf(logfile , "  |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	// fprintf(logfile , "  |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	// fprintf(logfile , "  |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	// fprintf(logfile, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
	// fprintf(logfile, "   |-Protocol : %d\n", (unsigned int)iph->protocol);
	// fprintf(logfile, "   |-Checksum : %d\n", ntohs(iph->check));
	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));

	//////////////////////////* Transport; TCP Header */////////////////////////
	////////////////////////////////////////////////////////////////////////////
	struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	// fprintf(logfile, "\n");
	// fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "   |-Source Port      : %u\n", ntohs(tcph->source));
	fprintf(logfile, "   |-Destination Port : %u\n", ntohs(tcph->dest));
	// fprintf(logfile, "   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	// fprintf(logfile, "   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	// fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
	// fprintf(logfile , "  |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	// fprintf(logfile , "  |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	// fprintf(logfile, "   |-Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	// fprintf(logfile, "   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	// fprintf(logfile, "   |-Push Flag            : %d\n", (unsigned int)tcph->psh);
	// fprintf(logfile, "   |-Reset Flag           : %d\n", (unsigned int)tcph->rst);
	// fprintf(logfile, "   |-Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	// fprintf(logfile, "   |-Finish Flag          : %d\n", (unsigned int)tcph->fin);
	// fprintf(logfile, "   |-Window         : %d\n", ntohs(tcph->window));
	// fprintf(logfile, "   |-Checksum       : %d\n", ntohs(tcph->check));
	// fprintf(logfile, "   |-Urgent Pointer : %d\n", tcph->urg_ptr);

	//////////////////* Aplication; Payload (Calculator) Header *///////////////
	////////////////////////////////////////////////////////////////////////////
	struct calculatorPacket *api_data = (struct calculatorPacket *)(Buffer + sizeof(struct ethhdr) + iph->ihl * 4 + tcph->doff * 4);
	
	//fprintf(logfile, "   |-Timestamp        : %u\n", ntohl(api_data->unixtime));
	time_t timestamp = header->ts.tv_sec;
	struct tm *time_struct = gmtime(&timestamp);
	fprintf(logfile, "   |-Timestamp        : %s\n", asctime(time_struct));
	fprintf(logfile, "   |-Total_length     : %hu\n", ntohs(api_data->length));
	fprintf(logfile, "   |-C_flag           : %hu\n", api_data->c_flag);
	fprintf(logfile, "   |-S_flag           : %hu\n", api_data->s_flag);
	fprintf(logfile, "   |-T_flag           : %hu\n", api_data->t_flag);
	fprintf(logfile, "   |-Status_code      : %hu\n", (api_data->status) >> 2);
	fprintf(logfile, "   |-Cache_control    : %hu\n", ntohs(api_data->cache));
	// fprintf(logfile, "   |-padding             : %hu\n\n", api_data->padding);

	///////////////////////////////////* DATA */////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA                         ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "TCP Header\n");
	PrintData(Buffer + iphdrlen, tcph->doff * 4);

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + header_size, Size - header_size);
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

	case 6: // TCP Protocol
		++tcp;
		print_tcp_packet(packet, size, header);
		break;

	default: // Some Other Protocol like ARP etc.
		++others;
		break;
	}
	fflush(logfile);
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

	case 6: // TCP Protocol
		++tcp;
		print_tcp_packet(packet, size, header);
		break;

	default: // Some Other Protocol like ARP etc.
		++others;
		break;
	}
	fflush(logfile);
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
	logfile = fopen("319096251_213934599.txt", "w");
	if (logfile == NULL)
	{
		printf("Unable to create file.");
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
	fclose(logfile);	// Close the logfile
	return 0;
}
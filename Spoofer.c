#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>  //Provides declarations for sockets
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h>  //Provides declarations for ip header
#include <net/ethernet.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

unsigned short in_cksum(unsigned short *, int);

/* ICMP Header  */
struct icmpheader
{
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; // Checksum for ICMP Header and data
  unsigned short int icmp_id;     // Used for identifying request
  unsigned short int icmp_seq;    // Sequence number
};

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport; /* source port */
  u_int16_t udp_dport; /* destination port */
  u_int16_t udp_ulen;  /* udp length */
  u_int16_t udp_sum;   /* udp checksum */
};

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};


struct tcpheader
{
  unsigned short int tcph_srcport;
  unsigned short int tcph_destport;
  unsigned int tcph_seqnum;
  unsigned int tcph_acknum;
  unsigned char tcph_reserved : 4, tcph_offset : 4;
  // unsigned char tcph_flags;
  unsigned int
      tcp_res1 : 4,  /*little-endian*/
      tcph_hlen : 4, /*length of tcp header in 32-bit words*/
      tcph_fin : 1,  /*Finish flag "fin"*/
      tcph_syn : 1,  /*Synchronize sequence numbers to start a connection*/
      tcph_rst : 1,  /*Reset flag */
      tcph_psh : 1,  /*Push, sends data to the application*/
      tcph_ack : 1,  /*acknowledge*/
      tcph_urg : 1,  /*urgent pointer*/
      tcph_res2 : 2;

  unsigned short int tcph_win;
  unsigned short int tcph_chksum;
  unsigned short int tcph_urgptr;
};

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

void send_TCP_spoof()
{
  char buffer[1500];
  memset(buffer, 0, 1500);
  struct ipheader *ip = (struct ipheader *)buffer;
  struct tcpheader *tcph = (struct tcpheader *)(buffer + sizeof(struct ipheader));

  /*********************************************************
     Step 1: Fill in the TCP data field.
   ********************************************************/
  char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcpheader);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy(data, msg, data_len);

  /*********************************************************
     Step 2: Fill in the TCP header.
   ********************************************************/
  tcph->tcph_srcport = htons(12345);
  tcph->tcph_destport = htons(9090);
  tcph->tcph_seqnum = htonl(1);
  tcph->tcph_syn = 1;
  tcph->tcph_ack = 0;
  tcph->tcph_win = htons(32767);
  tcph->tcph_chksum = in_cksum((unsigned short *)tcph, sizeof(struct tcpheader));
  tcph->tcph_urgptr = 0;
  tcph->tcph_hlen = 5;
  tcph->tcph_offset = 5;

  /*********************************************************
     Step 3: Fill in the IP header.
   ********************************************************/
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_tos = 0;
  ip->iph_ttl = 40;
  ip->iph_ident = htons(54321);
  ip->iph_offset = 0;
  ip->iph_sourceip.s_addr = inet_addr("10.0.2.15");
  ip->iph_destip.s_addr = inet_addr("127.0.0.1");
  ip->iph_protocol = IPPROTO_TCP;
  ip->iph_chksum = htons(in_cksum((unsigned short *)buffer, (sizeof(struct ipheader) + sizeof(struct tcpheader))));
  ip->iph_len = htons(sizeof(struct ipheader) +
                      sizeof(struct tcpheader) + data_len);

  /*********************************************************
     Step 4: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);

  return;
}

void send_ICMP_spoof()
{
  char buffer[1500];
  memset(buffer, 0, 1500);

  /*********************************************************
     Step 1: Fill in the ICMP header.
   ********************************************************/
  struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; // ICMP Type: 8 is request, 0 is reply.
  icmp->icmp_code = 0; // Identifier (16 bits): some number to trace the response.
  icmp->icmp_id = 18;  // Sequence Number (16 bits): starts at 0
  // Calculate the checksum for integrity
  icmp->icmp_seq = 0;
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

  /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
  struct ipheader *ip = (struct ipheader *)buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr("127.0.0.1");
  ip->iph_destip.s_addr = inet_addr("10.9.0.1");
  ip->iph_protocol = IPPROTO_ICMP;
  ip->iph_len = htons(sizeof(struct ipheader) +
                      sizeof(struct icmpheader));

  /*********************************************************
     Step 3: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);

  return;
}

void send_UDP_spoof()
{
  char buffer[1500];
  memset(buffer, 0, 1500);
  struct ipheader *ip = (struct ipheader *)buffer;
  struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));

  /*********************************************************
     Step 1: Fill in the UDP data field.
   ********************************************************/
  char *data = buffer + sizeof(struct ipheader) +
               sizeof(struct udpheader);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy(data, msg, data_len);

  /*********************************************************
     Step 2: Fill in the UDP header.
   ********************************************************/
  udp->udp_sport = htons(12345);
  udp->udp_dport = htons(9090);
  udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
  udp->udp_sum = 0; /* Many OSes ignore this field, so we do not
                       calculate it. */

  /*********************************************************
     Step 3: Fill in the IP header.
   ********************************************************/
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr("10.0.2.15");
  ip->iph_destip.s_addr = inet_addr("8.8.8.8");
  ip->iph_protocol = IPPROTO_UDP;
  ip->iph_len = htons(sizeof(struct ipheader) +
                      sizeof(struct udpheader) + data_len);

  /*********************************************************
     Step 4: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);

  return;
}

int main(int count, char *argv[])
{
  enum proto
  {
    ICMP,
    UDP,
    TCP
  };

  enum proto user_proto;

  if (strcmp(argv[1], "ICMP") == 0)
    user_proto = ICMP;
  else if (strcmp(argv[1], "UDP") == 0)
    user_proto = UDP;
  else if (strcmp(argv[1], "TCP") == 0)
    user_proto = TCP;

  switch (user_proto) // Check the Protocol and do accordingly...
  {
  case 0: // ICMP Protocol
    send_ICMP_spoof();
    break;

  case 1: // UDP Protocol
    send_UDP_spoof();
    break;

  case 2: // TCP Protocol
    send_TCP_spoof();
    break;

  default: // Some Other Protocol like ARP etc.
    perror("Invalid Protocol");
    break;
  }

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
  sum += (sum >> 16);                 // add carry
  return (unsigned short)(~sum);
}
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> //Provides declarations for sockets
#include <netinet/in.h>
#include <netinet/ip.h> //Provides declarations for ip header
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define HOST_PORT 9998

int connect_to_host(char *); // open socket to transfer message from gateway to a specified host
int send_to_host(char *); // send to host the message received in gateway
int open_gateway(); // open socket to receive from any host messages in gateway
int recv_from_any(); // listen for incoming messages and update host if one was received

struct sockaddr_in HostAddr;
struct sockaddr_in GateAddr;
struct sockaddr_in clientAddr;
socklen_t clientAddressLen = sizeof(clientAddr);
int host_sock = -1;
int gate_sock = -1;

int connect_to_host(char *host_ip)
{
    // Create socket
    if ((host_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        printf("Could not create socket : %d", errno);
        return -1;
    }

    // Setup the server address structure.
    // Port and IP should be filled in network byte order
    memset(&HostAddr, 0, sizeof(HostAddr));
    HostAddr.sin_family = AF_INET;
    HostAddr.sin_port = htons(HOST_PORT);
    int rval = inet_pton(AF_INET, (const char *)host_ip, &HostAddr.sin_addr);
    if (rval <= 0)
    {
        printf("inet_pton() failed");
        return -1;
    }
    return 1;
}

int send_to_host(char *message)
{
    char * host_message = message;
    int messageLen = strlen(host_message) + 1;
    // send the message
    if (sendto(host_sock, host_message, messageLen, 0, (struct sockaddr *)&HostAddr, sizeof(HostAddr)) == -1)
    {
        printf("sendto() failed with error code  : %d", errno);
        return -1;
    }

    struct sockaddr_in fromAddress;
    // Change type variable from int to socklen_t: int fromAddressSize = sizeof(fromAddress);
    socklen_t fromAddressSize = sizeof(fromAddress);

    memset((char *)&fromAddress, 0, sizeof(fromAddress));
    
    return 1;
}

int main()
{
    char * message = "hello";

    connect_to_host("127.0.0.1");
    send_to_host(message);
    close(host_sock);

    return 0;
}
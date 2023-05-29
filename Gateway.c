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

#define SERVER_IP_ADDRESS "127.0.0.1"

#define P 9998
#define HOST_PORT (P + 1)
#define ANY_HOST_PORT P

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

char buffer[80] = {'\0'};
char message[] = "I am Server\n"; // message to send to client
int messageLen = 14;

int open_gateway()
{

    // Create socket
    if ((gate_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) // In Windows -1 is SOCKET_ERROR
    {
        printf("Could not create socket : %d", errno);
        return -1;
    }

    // setup Server address structure
    memset((char *)&GateAddr, 0, sizeof(GateAddr));
    GateAddr.sin_family = AF_INET;
    GateAddr.sin_port = htons(P);
    inet_pton(AF_INET, (const char *)SERVER_IP_ADDRESS, &(GateAddr.sin_addr));

    // Bind
    if (bind(gate_sock, (struct sockaddr *)&GateAddr, sizeof(GateAddr)) == -1)
    {
        printf("bind() failed with error code : %d", errno);
        return -1;
    }
    printf("Waiting for clients\n");
    memset((char *)&clientAddr, 0, sizeof(clientAddr));
    return 1;
}

int recv_from_any()
{
    // keep listening for data
    while (1)
    {
        fflush(stdout);

        // zero client address
        memset((char *)&clientAddr, 0, sizeof(clientAddr));
        clientAddressLen = sizeof(clientAddr);

        // clear the buffer by filling null, it might have previously received data
        memset(buffer, '\0', sizeof(buffer));

        int recv_len = -1;

        // try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(gate_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&clientAddr, &clientAddressLen)) == -1)
        {
            printf("recvfrom() failed with error code : %d", errno);
            break;
        }

        char clientIPAddrReadable[32] = {'\0'};
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIPAddrReadable, sizeof(clientIPAddrReadable));

        // print details of the client/peer and the data received
        printf("Received packet from %s:%d\n", clientIPAddrReadable, ntohs(clientAddr.sin_port));
        printf("Data is: %s\n", buffer);

        float rand = ((float) random()) / ((float)RAND_MAX);
        printf("Random number is: %f\n", rand);

        if (rand < 0.5)
        {
            printf("Packet lost\n");
            continue;
        } else
        {
            printf("Packet received\n");
            send_to_host(buffer);
        }
    }
    return 1;
}

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

int main(int count, char *argv[])
{

    connect_to_host(argv[1]);
    open_gateway();
    recv_from_any();

    close(host_sock);
    close(gate_sock);

    return 0;
}
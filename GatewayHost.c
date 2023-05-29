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

#define P 9999

int connect_to_host(char *); // open socket to transfer message from gateway to a specified host
int send_to_host(char *);    // send to host the message received in gateway
int open_gateway();          // open socket to receive from any host messages in gateway
int recv_from_any();         // listen for incoming messages and update host if one was received

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

        printf("Packet received\n");
    }
    return 1;
}

int main()
{
    open_gateway();
    recv_from_any();

    close(host_sock);
    close(gate_sock);

    return 0;
}
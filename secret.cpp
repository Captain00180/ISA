#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>


#define EXIT_SUCCESS 0
#define EXIT_ERROR 1

#define MAX_PACKET_SIZE 1500

typedef struct icmp_packet {
    struct icmphdr header;
    char data[MAX_PACKET_SIZE - sizeof (struct icmphdr)];
} icmp_packet;

void exit_error(const char *msg) {
    fprintf(stderr, "%s", msg);
    exit(EXIT_ERROR);
}


int main(int argc, char *argv[]) {
    // Determines whether the program is being executed as a client or server
    int LISTEN_MODE = 0;

    /*                  *
     * Argument parsing *
     *                  */

    int r_flag = 0;
    int s_flag = 0;
    int l_flag = 0;

    char *file = NULL;
    char *host = NULL;

    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "r:s:l")) != -1) {
        switch (c) {
            case 'r':
                r_flag = 1;
                file = optarg;
                break;
            case 's':
                s_flag = 1;
                host = optarg;
                break;
            case 'l':
                l_flag = 1;
                break;
            default:
                exit_error("Error; Unexpected argument!\n");
        }
    }

    //printf("rflag: %d - %s\nsflag: %d - %s \nlflag: %d\n", r_flag, file, s_flag, host, l_flag);
    //printf("optind: %d", optind);

    // '-l' option can't be used in combination with other options
    if (l_flag && (r_flag || s_flag)) {
        exit_error("Error: '-l'  option can't be used in combination with other options!\n");
    }


    // '-r' and '-s' options are required
    if (!l_flag && (!r_flag || !s_flag)) {
        exit_error("Error: Missing arguments!\n");
    }

    LISTEN_MODE = l_flag;

    struct addrinfo hints{};
    struct addrinfo *root = NULL;
    /*                  *
     *    Preparation   *
     *                  */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    // Get the server IP address from entered hostname/IP
    if ((getaddrinfo(host, NULL, &hints, &root)) != 0) {
        exit_error("Error: getaddrinfo() failed!\n");
    }

    //char ip[50];
    //struct sockaddr_in *;
    //inet_ntop(root->ai_family, &(((struct sockaddr_in *) root->ai_addr)->sin_addr), ip, 100);
    //printf("ip: %s\n", ip);

    // Create IPV4 and IPV6 sockets
    int sock_ipv4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sock_ipv6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock_ipv4 == -1 || sock_ipv6 == -1){
        exit_error("Error: Couldn't create socket!\n");
    }

    icmp_packet packet {};
    packet.header.checksum = 0;
    packet.header.type = ICMP_ECHO;
    packet.header.code = 0;

    memcpy(packet.data, "Hello, world!", 13);


    if (sendto(sock_ipv4, &packet, sizeof(packet), 0, (struct sockaddr *) (root->ai_addr), root->ai_addrlen) == -1)
    {
        exit_error("Error: Couldn't send packet!\n");
    }

//    // Iterate through all addresses returned by getaddrinfo() and try to send the message
//    while (root != NULL) {
//
//    }

    return 0;
}
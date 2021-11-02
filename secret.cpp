#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <pcap.h>


#define EXIT_SUCCESS 0
#define EXIT_ERROR 1

#define MAX_PACKET_SIZE 1500

typedef struct icmpv4_packet {
    struct icmphdr header;
    char data[MAX_PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr)];
} icmpv4_packet;

typedef struct icmpv6_packet {
    struct icmp6_hdr header;
    char data[MAX_PACKET_SIZE - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr)];
} icmpv6_packet;


void initialize_icmpv4_packet(icmpv4_packet *pack) {
    pack->header.checksum = 0;
    pack->header.type = ICMP_ECHO;
    pack->header.code = 0;
}

void initialize_icmpv6_packet(icmpv6_packet *pack) {
    pack->header.icmp6_cksum = 0;
    pack->header.icmp6_type = ICMP6_ECHO_REQUEST;
    pack->header.icmp6_code = 0;
}

void exit_error(const char *msg) {
    fprintf(stderr, "%s", msg);
    exit(EXIT_ERROR);
}

void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *data){

    // Points to the beginning of the IP header.
    // Capturing on 'any' device causes pcap to replace a 14B ethernet header with a
    // 16B 'cooked header'. This skips the header and gets to the start of the IP header
    uint8_t *iphdr_start = (uint8_t *) (data + 16);
    // Gets the first 8 bits of the IP header, applies a mask to extract
    // the first 4 bits ( 240d == 11110000b ) and shifts it to get the first
    // 4 bits as a number
    uint8_t protocol_version = (240 & *iphdr_start) >> 4;

    if (protocol_version == 4){
        struct iphdr *iphdr = (struct iphdr*)(data + 16);
        if (iphdr->protocol == 1)
        {
            printf("ICMP packet caught!\n");
            icmpv4_packet *packet = (icmpv4_packet *) ( ((char*)iphdr) + sizeof (struct iphdr));
            printf("Packet contents: \nFile size = %d\nFile name = %s\n", packet->header.code, packet->data);

        }
    }
    else if (protocol_version == 6)
    {
        struct ip6_hdr *ip6hdr = (struct ip6_hdr*)(data + 16);
        if (ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58)
        {
            printf("ICMPv6 packet caught!\n");
            icmpv6_packet *packet = (icmpv6_packet *) ( ((char*)ip6hdr) + sizeof (struct ip6_hdr));
            printf("Packet contents: \nFile size = %d\nFile name = %s\n", packet->header.icmp6_code, packet->data);
        }
    }


}

int server(){
    pcap_t *device = NULL;
    char errbuf [PCAP_ERRBUF_SIZE];

    device = pcap_open_live("any", 65535, 1, 1000, errbuf);
    if (device == NULL){
        fprintf(stderr, "Error: Pcap live open failed! [%s]\n", errbuf);
        exit(1);
    }
    printf("Started sniffing\n");
    pcap_loop(device, -1, handle_packet, NULL);
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
//    if (!l_flag && (!r_flag || !s_flag)) {
//        exit_error("Error: Missing arguments!\n");
//    }

    LISTEN_MODE = l_flag;

    if (LISTEN_MODE)
    {
        server();
        return 0;
    }

    struct addrinfo hints{};
    struct addrinfo *server_address = NULL;
    /*                  *
     *    Preparation   *
     *                  */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    // Get the server IP address from entered hostname/IP
    if ((getaddrinfo(host, NULL, &hints, &server_address)) != 0) {
        exit_error("Error: getaddrinfo() failed!\n");
    }

    char ip[50];
    inet_ntop(server_address->ai_family, &(((struct sockaddr_in *) server_address->ai_addr)->sin_addr), ip, 50);
    printf("ip: %s\n", ip);

    // Create IPV4 and IPV6 sockets
    int sock_ipv4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sock_ipv6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock_ipv4 == -1 || sock_ipv6 == -1) {
        exit_error("Error: Couldn't create socket!\n");
    }

    icmpv4_packet packet_v4{};
    initialize_icmpv4_packet(&packet_v4);

    icmpv6_packet packet_v6{};
    initialize_icmpv6_packet(&packet_v6);

    FILE *input_file = fopen(file, "rb");
    if (input_file == NULL) {
        exit_error("Error: Couldn't open file!\n");
    }

    // Get the size of the file
    size_t file_size = strlen(file) * sizeof(char);
    struct stat file_stats;

    if (fstat(fileno(input_file), &file_stats) != 0){
        exit_error("Error: Couldn't get file information!\n");
    }
    file_size += file_stats.st_size;

    //unsigned char buff[100];
    //fread(buff, 99, 1, input_file);
    //printf("%s\n", buff);

    // Iterate through all addresses returned by getaddrinfo() and try to send the first packet
    // which contains metadata about the file (name and number of packets)
    for (; server_address != NULL; server_address = server_address->ai_next) {
        int res = 0;
        if (server_address->ai_family == AF_INET) {
            memcpy(packet_v4.data, file, strlen(file));
            packet_v4.header.code = file_size;
            res = sendto(sock_ipv4, &packet_v4, sizeof(packet_v4), 0, (struct sockaddr *) (server_address->ai_addr),
                         server_address->ai_addrlen);
        } else {
            memcpy(packet_v6.data, file, strlen(file));
            packet_v6.header.icmp6_code = file_size;
            res = sendto(sock_ipv6, &packet_v6, sizeof(packet_v6), 0, (struct sockaddr *) (server_address->ai_addr),
                         server_address->ai_addrlen);
        }

        if (res == -1) {
            fprintf(stderr, "Error: Couldn't send packet!\n");
            continue;
        } else {
            printf("Sendto success!\n");
        }
    }


    // AES encryption
//    const unsigned char message[] = "Hello, world!";
//    const unsigned char user_key[] = "xjanus11";
//
//    auto *out = static_cast<unsigned char *>(calloc(1, 150));
//
//    AES_KEY enc_key;
//    AES_KEY dec_key;
//
//    AES_set_encrypt_key(user_key, 128, &enc_key);
//    AES_set_decrypt_key(user_key, 128, &dec_key);
//
//    AES_encrypt(message, out, &enc_key);
//    printf("Encrypted: %s\n", out);
//
//    AES_decrypt(out, out, &dec_key);
//
//    printf("Decrypted: %s\n", out);



    return 0;
}
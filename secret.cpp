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
#include <libgen.h>
#include <unistd.h>
#include <fstream>

#define EXIT_SUCCESS 0
#define EXIT_ERROR 1

#define START_TRANSMISSION 31
#define END_TRANSMISSION 42

#define MAX_PACKET_SIZE 1500
#define MAX_PAYLOAD_LEN_IPV4 (MAX_PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr))
#define MAX_PAYLOAD_LEN_IPV6 (MAX_PACKET_SIZE - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr))

char * RECEIVE_BUFFER = NULL;
char * FILE_NAME = NULL;
int FILE_SIZE = 0;
int PACKETS_RECEIVED = 0;
int PACKETS_SENT = 1;

typedef struct icmpv4_packet {
    struct icmphdr header;
    char data[MAX_PAYLOAD_LEN_IPV4];
} icmpv4_packet;

typedef struct icmpv6_packet {
    struct icmp6_hdr header;
    char data[MAX_PAYLOAD_LEN_IPV6];
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
            //printf("ICMP packet caught!\n");
            icmpv4_packet *packet = (icmpv4_packet *) ( ((char*)iphdr) + sizeof (struct iphdr));
            //printf("Packet contents: \nFile size = %d\nFile name = %s\n", packet->header.un.echo.id, packet->data);
            // First packet of the transmission - allocate buffer
            if (packet->header.code == START_TRANSMISSION)
            {
                // packet->header.un.echo.id of the first packet contains the size of the file
                RECEIVE_BUFFER = (char*) (calloc(1, packet->header.un.echo.id));
                FILE_NAME = (char*) (calloc(1, strlen(packet->data)));
                if (RECEIVE_BUFFER == NULL || FILE_NAME == NULL)
                {
                    exit_error("Error: Couldn't allocate server buffers!\n");
                }
                memcpy(FILE_NAME, packet->data, strlen(packet->data));
            }
            else if(packet->header.code == END_TRANSMISSION)
            {
                FILE * output = fopen(FILE_NAME, "w");
                if (output == NULL)
                {
                    exit_error("Error: Couldn't create output file!\n");
                }
                if (fputs(RECEIVE_BUFFER, output) != 0)
                {
                    exit_error("Error: Couldn't write to file!\n");
                }
                fclose(output);
                free(RECEIVE_BUFFER);
                RECEIVE_BUFFER = NULL;
                free(FILE_NAME);
                FILE_NAME = NULL;
            }
            else
            {
                strcat(RECEIVE_BUFFER, packet->data);
            }

        }
    }
    else if (protocol_version == 6)
    {
        struct ip6_hdr *ip6hdr = (struct ip6_hdr*)(data + 16);
        if (ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58)
        {
            //printf("ICMPv6 packet caught!\n");
            icmpv6_packet *packet = (icmpv6_packet *) ( ((char*)ip6hdr) + sizeof (struct ip6_hdr));
            if (packet->header.icmp6_type == ICMP6_ECHO_REQUEST) {
                PACKETS_RECEIVED++;
                //printf("Packet contents: \nFile size = %d\nFile name = %s\n", packet->header.icmp6_dataun.icmp6_un_data32[0], packet->data);
                if (packet->header.icmp6_code == START_TRANSMISSION) {
                    // packet->header.icmp6_dataun.icmp6_un_data32[0] of the first packet contains the size of the file
                    RECEIVE_BUFFER = (char *) (calloc(1, packet->header.icmp6_dataun.icmp6_un_data32[0]));
                    FILE_SIZE = packet->header.icmp6_dataun.icmp6_un_data32[0];
                    FILE_NAME = (char *) (calloc(1, strlen(packet->data)));
                    if (RECEIVE_BUFFER == NULL || FILE_NAME == NULL) {
                        exit_error("Error: Couldn't allocate server buffers!\n");
                    }
                    memcpy(FILE_NAME, basename(packet->data), strlen(basename(packet->data)));
                } else if (packet->header.icmp6_code == END_TRANSMISSION) {

                    strncat(RECEIVE_BUFFER, packet->data, packet->header.icmp6_dataun.icmp6_un_data32[0]);

                    std::ofstream output;
                    output.open(FILE_NAME, std::ios::binary | std::ios::out);
                    if (!output.is_open())
                    {
                        exit_error("Error: Couldn't create output file!\n");
                    }
                    output.write(RECEIVE_BUFFER, FILE_SIZE - strlen(FILE_NAME));
//
//                    FILE *output = fopen(FILE_NAME, "w+");
//                    if (output == NULL) {
//                        exit_error("Error: Couldn't create output file!\n");
//                    }
//                    if (fputs(RECEIVE_BUFFER, output) < 0) {
//                        exit_error("Error: Couldn't write to file! \n");
//                    }
//                    fclose(output);
                    free(RECEIVE_BUFFER);
                    RECEIVE_BUFFER = NULL;
                    free(FILE_NAME);
                    FILE_NAME = NULL;
                    //printf("RECEVIED%d\n", PACKETS_RECEIVED);
                } else {
                    printf("Packet #%d \n", PACKETS_RECEIVED);
                    strncat(RECEIVE_BUFFER, packet->data, packet->header.icmp6_dataun.icmp6_un_data32[0]);

                }
            }
        }
    }


}

void server(){
    pcap_t *device = NULL;
    char errbuf [PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    device = pcap_open_live("any", 65535, 1, 1000, errbuf);
    if (device == NULL){
        fprintf(stderr, "Error: Pcap live open failed! [%s]\n", errbuf);
        exit(1);
    }

    if (pcap_compile(device, &filter, "icmp or icmp6", 0, PCAP_NETMASK_UNKNOWN) == -1){
        exit_error("Error: Couldn't compile filter!\n");
    }
    if (pcap_setfilter(device, &filter) == -1){
        exit_error("Error: Couldn't apply filter!\n");
    }
    printf("Started sniffing\n");
    pcap_loop(device, -1, handle_packet, NULL);
}


void parse_arguments(int argc, char *argv[], int *LISTEN_MODE, char **file, char **host) {
    int r_flag = 0;
    int s_flag = 0;
    int l_flag = 0;
    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "r:s:l")) != -1) {
        switch (c) {
            case 'r':
                r_flag = 1;
                *file = optarg;
                break;
            case 's':
                s_flag = 1;
                *host = optarg;
                break;
            case 'l':
                l_flag = 1;
                break;
            default:
                exit_error("Error; Unexpected argument!\n");
        }
    }
    //'-r' and '-s' options are required
    if (!l_flag && (!r_flag || !s_flag)) {
        exit_error("Error: Missing arguments!\n");
    }

    *LISTEN_MODE = l_flag;
}

struct addrinfo *send_meta_packet(const char *file, struct addrinfo *server_address, int sock_ipv4, int sock_ipv6, icmpv4_packet packet_v4,
                      icmpv6_packet packet_v6, size_t file_size) {
    // Iterate through all addresses returned by getaddrinfo() and try to send the first packet
    // which contains metadata about the file (name and number of packets)
    for (; server_address != NULL; server_address = server_address->ai_next) {
        int res = 0;
        if (server_address->ai_family == AF_INET) {
            // IPv4 address
            // Packet data contains only file name
            memcpy(packet_v4.data, file, strlen(file));
            // Using the 'echo.id' field of the header to communicate the file size to server
            packet_v4.header.un.echo.id = file_size + strlen(file);
            // Using the 'code' field of the header to indicate start/end of file transmission
            packet_v4.header.code = START_TRANSMISSION;
            // Send the message
            res = sendto(sock_ipv4, &packet_v4, sizeof(packet_v4), 0, (struct sockaddr *) (server_address->ai_addr),
                         server_address->ai_addrlen);
            memset(packet_v4.data, 0, MAX_PAYLOAD_LEN_IPV4);
        } else {
            // IPv6 address
            // Packet data contains only file name
            memcpy(packet_v6.data, file, strlen(file));
            // Using the 'data32' field of the header to communicate the file size to server
            packet_v6.header.icmp6_dataun.icmp6_un_data32[0] = file_size + strlen(file);
            // Using the 'code' field of the header to indicate start/end of file transmission
            packet_v6.header.icmp6_code = START_TRANSMISSION;
            // Send the message
            res = sendto(sock_ipv6, &packet_v6, sizeof(packet_v6), 0, (struct sockaddr *) (server_address->ai_addr),
                         server_address->ai_addrlen);
            memset(packet_v6.data, 0, MAX_PAYLOAD_LEN_IPV6);
        }

        if (res == -1) {
            // Packet couldn't be sent. Try the next server address
            fprintf(stderr, "Error: Couldn't send packet! Trying the next address...\n");
            continue;
        } else {
            // Packet was successfully sent. Use this address for the rest of the communication
            break;
        }
    }
    return server_address;
}

int client(const char *file, const char *host) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    // Support IPv4 and IPv6 addresses
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    struct addrinfo *server_address = NULL;
    // Get the server IP address from entered hostname/IP
    if ((getaddrinfo(host, NULL, &hints, &server_address)) != 0) {
        exit_error("Error: getaddrinfo() failed!\n");
    }

    // Create IPV4 and IPV6 sockets
    int sock_ipv4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sock_ipv6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock_ipv4 == -1 || sock_ipv6 == -1) {
        exit_error("Error: Couldn't create socket!\n");
    }

    // Prepare icmpv4 and icmpv6 packets. They contain a icmp header and
    // a data buffer
    // Depending on the server address from getaddrinfo(), icmpv4 or v6 packet
    // will be used for the communication
    icmpv4_packet packet_v4{};
    initialize_icmpv4_packet(&packet_v4);

    icmpv6_packet packet_v6{};
    initialize_icmpv6_packet(&packet_v6);

    // Open the source file
    FILE *input_file = fopen(file, "rb");
    if (input_file == NULL) {
        exit_error("Error: Couldn't open file!\n");
    }

    // Get the size of the file. Sum it up with the file name for payload length

    struct stat file_stats{};
    if (fstat(fileno(input_file), &file_stats) != 0){
        exit_error("Error: Couldn't get file information!\n");
    }
    size_t file_size =  file_stats.st_size;

    //unsigned char buff[100];
//fread(buff, 99, 1, input_file);
//printf("%s\n", buff);

    // Send the first packet, containing file name and file size
    server_address = send_meta_packet(file, server_address, sock_ipv4, sock_ipv6, packet_v4, packet_v6, file_size);

    if (server_address == NULL){
        exit_error("Error: Couldn't reach the server!\n");
    }
    // Buffer which holds data from the file
    size_t n_of_bytes = 0;
    size_t max_data_len = MAX_PAYLOAD_LEN_IPV6;
    while(file_size > 0){
        unsigned char buff[MAX_PACKET_SIZE] = {0};
        //printf("________________________NEW PACKET__________________\n");
        n_of_bytes = (file_size >  max_data_len) ? max_data_len : file_size;
        file_size -= n_of_bytes;
        if (fread(buff, 1, n_of_bytes, input_file) != n_of_bytes){
            exit_error("Error reading file!\n");
        }
        // IPv4
        if (server_address->ai_family == AF_INET)
        {
            if (file_size == 0){
                packet_v4.header.code = END_TRANSMISSION;
            }
            memcpy(packet_v4.data, buff, n_of_bytes);
            if (sendto(sock_ipv4, &packet_v4, sizeof(packet_v4), 0, (struct sockaddr *) (server_address->ai_addr),
                       server_address->ai_addrlen) == -1) {
                exit_error("Error: Couldn't send packet!\n");
            }
            memset(&packet_v4.data, 0, max_data_len);
        }
        // IPv6
        else
        {
            PACKETS_SENT ++;
            if (file_size == 0){
                packet_v6.header.icmp6_code = END_TRANSMISSION;
            }
            // Contains the size of the current message
            packet_v6.header.icmp6_dataun.icmp6_un_data32[0] = n_of_bytes;
            memcpy(packet_v6.data, buff, n_of_bytes);
            if (sendto(sock_ipv6, &packet_v6, sizeof(packet_v6), 0, (struct sockaddr *) (server_address->ai_addr),
                       server_address->ai_addrlen) == -1) {
                exit_error("Error: Couldn't send packet!\n");
            }
            printf("Packet #%d \n", PACKETS_SENT);
            usleep(5000);
            memset(&packet_v6.data, 0, max_data_len);
        }

    }
    printf("%d\n", PACKETS_SENT);
    return 0;
}

int main(int argc, char *argv[]) {
    // Determines whether the program is being executed as a client or server
    int LISTEN_MODE = 0;
    char *file = NULL;
    char *host = NULL;

    parse_arguments(argc, argv, &LISTEN_MODE, &file, &host);

    if (LISTEN_MODE)
    {
        server();
        return 0;
    }

    client(file, host);

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
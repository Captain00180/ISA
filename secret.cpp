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
#include <vector>

/*****************************************************
 *      Macros, global variables and structures      *
 ****************************************************/

#define EXIT_SUCCESS 0
#define EXIT_ERROR 1

#define START_TRANSMISSION 31
#define END_TRANSMISSION 42

#define MAX_PACKET_SIZE 1500
#define MAX_PAYLOAD_LEN_IPV4 (MAX_PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr))
#define MAX_PAYLOAD_LEN_IPV6 (MAX_PACKET_SIZE - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr))


std::vector<char> RECEIVE_BUFFER;
char *FILE_NAME = NULL;
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

/*****************************************************
 *            General function definitions           *
 ****************************************************/

/**
 * Terminates the program with an exit code
 * @param msg Message to be printed to stderr
 */
void exit_error(const char *msg) {
    fprintf(stderr, "%s", msg);
    exit(EXIT_ERROR);
}

/**
 * Parses program arguments from the command line
 * @param argc
 * @param argv
 * @param LISTEN_MODE Is set to 0 if application should be ran as a client, and to 1 if it should be ran as a server
 * @param file Is set to the name of the input file
 * @param host Is set to the hostname/ip address of the server
 */
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

/**
 * Returns the size of the file, indicated by the FILE pointer
 * @param input_file FILE pointer to the file
 * @return Size of the file, in bytes
 */
size_t get_file_size(FILE *input_file) {
    struct stat file_stats{};
    if (fstat(fileno(input_file), &file_stats) != 0) {
        exit_error("Error: Couldn't get file information!\n");
    }
    return file_stats.st_size;
}

/*****************************************************
 *            Server function definitions            *
 ****************************************************/

/**
 * Analyzes a received packet
 * @param user
 * @param header
 * @param data
 */
void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {

    // Points to the beginning of the IP header.
    // Capturing on 'any' device causes pcap to replace a 14B ethernet header with a
    // 16B 'cooked header'. This skips the header and gets to the start of the IP header
    uint8_t *iphdr_start = (uint8_t *) (data + 16);
    // Gets the first 8 bits of the IP header, applies a mask to extract
    // the first 4 bits ( 240d == 11110000b ) and shifts it to get the first
    // 4 bits as a number
    uint8_t protocol_version = (240 & *iphdr_start) >> 4;

    if (protocol_version == 4) {
        struct iphdr *iphdr = (struct iphdr *) (data + 16);
        if (iphdr->protocol == 1) {
            //printf("ICMP packet caught!\n");
            icmpv4_packet *packet = (icmpv4_packet *) (((char *) iphdr) + sizeof(struct iphdr));
            //printf("Packet contents: \nFile size = %d\nFile name = %s\n", packet->header.un.echo.id, packet->data);
            // First packet of the transmission - allocate buffer
            if (packet->header.code == START_TRANSMISSION) {
                // packet->header.un.echo.id of the first packet contains the size of the file
                //RECEIVE_BUFFER = (char*) (calloc(1, packet->header.un.echo.id));
                RECEIVE_BUFFER.reserve(packet->header.un.echo.id);
                FILE_NAME = (char *) (calloc(1, strlen(packet->data)));
                if (FILE_NAME == NULL) {
                    exit_error("Error: Couldn't allocate server buffers!\n");
                }
                memcpy(FILE_NAME, packet->data, strlen(packet->data));
            } else if (packet->header.code == END_TRANSMISSION) {
                FILE *output = fopen(FILE_NAME, "w");
                if (output == NULL) {
                    exit_error("Error: Couldn't create output file!\n");
                }
//                if (fputs(RECEIVE_BUFFER, output) != 0)
//                {
//                    exit_error("Error: Couldn't write to file!\n");
//                }
//                fclose(output);
//                free(RECEIVE_BUFFER);
//                RECEIVE_BUFFER = NULL;
//                free(FILE_NAME);
//                FILE_NAME = NULL;
            }
//            else
//            {
//                strcat(RECEIVE_BUFFER, packet->data);
//            }

        }
    } else if (protocol_version == 6) {
        struct ip6_hdr *ip6hdr = (struct ip6_hdr *) (data + 16);
        if (ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) {
            //printf("ICMPv6 packet caught!\n");
            icmpv6_packet *packet = (icmpv6_packet *) (((char *) ip6hdr) + sizeof(struct ip6_hdr));
            if (packet->header.icmp6_type == ICMP6_ECHO_REQUEST) {
                PACKETS_RECEIVED++;
                //printf("Packet contents: \nFile size = %d\nFile name = %s\n", packet->header.icmp6_dataun.icmp6_un_data32[0], packet->data);
                if (packet->header.icmp6_code == START_TRANSMISSION) {
                    // packet->header.icmp6_dataun.icmp6_un_data32[0] of the first packet contains the size of the file
                    RECEIVE_BUFFER.reserve(packet->header.icmp6_dataun.icmp6_un_data32[0]);
                    FILE_SIZE = packet->header.icmp6_dataun.icmp6_un_data32[0];
                    FILE_NAME = (char *) (calloc(1, strlen(packet->data)));
                    if (FILE_NAME == NULL) {
                        exit_error("Error: Couldn't allocate server buffers!\n");
                    }
                    memcpy(FILE_NAME, basename(packet->data), strlen(basename(packet->data)));
                } else if (packet->header.icmp6_code == END_TRANSMISSION) {

                    //strncat(RECEIVE_BUFFER, packet->data, packet->header.icmp6_dataun.icmp6_un_data32[0]);
                    for (uint32_t i = 0; i < packet->header.icmp6_dataun.icmp6_un_data32[0]; i++) {
                        RECEIVE_BUFFER.push_back(packet->data[i]);
                    }

                    std::ofstream output;
                    output.open(FILE_NAME, std::ios::binary | std::ios::out);
                    if (!output.is_open()) {
                        exit_error("Error: Couldn't create output file!\n");
                    }
                    for (auto &e : RECEIVE_BUFFER) {
                        output << e;
                    }
//
//                    FILE *output = fopen(FILE_NAME, "w+");
//                    if (output == NULL) {
//                        exit_error("Error: Couldn't create output file!\n");
//                    }
//                    if (fputs(RECEIVE_BUFFER, output) < 0) {
//                        exit_error("Error: Couldn't write to file! \n");
//                    }
//                    fclose(output);
                    //free(RECEIVE_BUFFER);
                    //RECEIVE_BUFFER = NULL;
                    RECEIVE_BUFFER.clear();
                    free(FILE_NAME);
                    FILE_NAME = NULL;
                    printf("RECEVIED%d\n", PACKETS_RECEIVED);
                    PACKETS_RECEIVED = 0;
                } else {
                    printf("Packet #%d \n", PACKETS_RECEIVED);
                    for (uint32_t i = 0; i < packet->header.icmp6_dataun.icmp6_un_data32[0]; i++) {
                        RECEIVE_BUFFER.push_back(packet->data[i]);
                    }

                }
            }
        }
    }


}

/**
 * Represents the behavior of a server. Contains the main loop of the server
 */
void server() {
    pcap_t *device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    device = pcap_open_live("any", 65535, 1, 1000, errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error: Pcap live open failed! [%s]\n", errbuf);
        exit(1);
    }

    if (pcap_compile(device, &filter, "icmp or icmp6", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        exit_error("Error: Couldn't compile filter!\n");
    }
    if (pcap_setfilter(device, &filter) == -1) {
        exit_error("Error: Couldn't apply filter!\n");
    }
    printf("Started sniffing\n");
    pcap_loop(device, -1, handle_packet, NULL);
}

/*****************************************************
 *            Client function definitions            *
 ****************************************************/
/**
 * Prepares an icmpv4 packet
 * @param pack Empty icmpv4 packet
 */
void initialize_icmpv4_packet(icmpv4_packet *pack) {
    pack->header.checksum = 0;
    pack->header.type = ICMP_ECHO;
    pack->header.code = 0;
}

/**
 * Prepares an icmpv6 packet
 * @param pack Empty icmpv6 packet
 */
void initialize_icmpv6_packet(icmpv6_packet *pack) {
    pack->header.icmp6_cksum = 0;
    pack->header.icmp6_type = ICMP6_ECHO_REQUEST;
    pack->header.icmp6_code = 0;
}

/**
 * Sends the first packet of the ICMP communication. This packet contains the size and name of the file
 * The function attempts to connect to all server addresses in 'server_address' and chooses to
 * initiate transmission on first successful connection.
 * @param file The name of the input file
 * @param server_address Pointer to a linked list containing all possible server addresses
 * @param sock_ipv4 Ipv4 socket
 * @param sock_ipv6 Ipv6 socket
 * @param packet_v4 Ipv4 packet
 * @param packet_v6 Ipv6 packet
 * @param file_size Size of the file to be sent
 * @return Address of the server, to which a connection attempt succeeded
 */
struct addrinfo *send_meta_packet(const char *file, struct addrinfo *server_address, int sock_ipv4, int sock_ipv6,
                                  icmpv4_packet packet_v4,
                                  icmpv6_packet packet_v6, size_t file_size) {
    // Iterate through all addresses returned by getaddrinfo() and try to send the first packet
    // which contains metadata about the file (name and number of packets)
    for (; server_address != NULL; server_address = server_address->ai_next) {
        int res = 0;
        if (server_address->ai_family == AF_INET) {
            // IPv4 address
            // Packet data contains only file name
            memcpy(packet_v4.data, file, strlen(file));
            // Using the 'gateway' field of the header to communicate the file size to server
            packet_v4.header.un.gateway = file_size + strlen(file);
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

/**
 * Prepares the Ipv6 packet for data transmission.
 * @param packet_v6 Ipv6 packet
 * @param file_size Size of the file to be sent
 * @param n_of_bytes Number of bytes of data from the input file, which this packet will hold
 * @param buff Buffer containing n_of_bytes bytes of data from the input file
 * @return Prepared Ipv6 packet
 */
icmpv6_packet prepare_packet_v6(icmpv6_packet packet_v6, size_t file_size, size_t n_of_bytes,
                                const unsigned char *buff) {
    // Contains the size of the current message
    packet_v6.header.icmp6_dataun.icmp6_un_data32[0] = n_of_bytes;
    PACKETS_SENT++;

    if (file_size == 0) {
        packet_v6.header.icmp6_code = END_TRANSMISSION;
    }

    memcpy(packet_v6.data, buff, n_of_bytes);
    return packet_v6;
}

/**
 * Prepares the Ipv4 packet for data transmission.
 * @param packet_v4 Ipv4 packet
 * @param file_size Size of the file to be sent
 * @param n_of_bytes Number of bytes of data from the input file, which this packet will hold
 * @param buff Buffer containing n_of_bytes bytes of data from the input file
 * @return Prepared Ipv4 packet
 */
icmpv4_packet prepare_packet_v4(icmpv4_packet packet_v4, size_t file_size, size_t n_of_bytes, const unsigned char *buff) {

    // Contains the size of the current message
    packet_v4.header.un.gateway = n_of_bytes;
    PACKETS_SENT++;

    // This packet is last to be sent - set the code accordingly, so the server knows communication is over
    if (file_size == 0) {
        packet_v4.header.code = END_TRANSMISSION;
    }

    memcpy(packet_v4.data, buff, n_of_bytes);
    return packet_v4;
}

/**
 * Represents the behaior of a client
 * @param file Name of the input file
 * @param host Hostname/IP address of the server
 * @return Success
 */
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

    // Get the size of the file.
    size_t file_size = get_file_size(input_file);

    // Send the first packet, containing file name and file size
    server_address = send_meta_packet(file, server_address, sock_ipv4, sock_ipv6, packet_v4, packet_v6, file_size);

    if (server_address == NULL) {
        exit_error("Error: Couldn't reach the server!\n");
    }

    // Number of bytes, which will be sent in the corresponding packet
    size_t n_of_bytes = 0;
    size_t max_data_len = MAX_PAYLOAD_LEN_IPV6;
    while (file_size > 0) {
        unsigned char buff[MAX_PACKET_SIZE] = {0};
        //printf("________________________NEW PACKET__________________\n");
        // Buffer which holds data from the file
        n_of_bytes = (file_size > max_data_len) ? max_data_len : file_size;
        file_size -= n_of_bytes;

        // Read the required amount of bytes from input file
        if (fread(buff, 1, n_of_bytes, input_file) != n_of_bytes) {
            exit_error("Error reading file!\n");
        }

        // IPv4
        if (server_address->ai_family == AF_INET) {
            packet_v4 = prepare_packet_v4(packet_v4, file_size, n_of_bytes, buff);

            if (sendto(sock_ipv4, &packet_v4, sizeof(packet_v4), 0, (struct sockaddr *) (server_address->ai_addr),
                       server_address->ai_addrlen) == -1) {
                exit_error("Error: Couldn't send packet!\n");
            }

            usleep(1000);
            memset(&packet_v4.data, 0, max_data_len);
        }
            // IPv6
        else if (server_address->ai_family == AF_INET6) {
            packet_v6 = prepare_packet_v6(packet_v6, file_size, n_of_bytes, buff);
            if (sendto(sock_ipv6, &packet_v6, sizeof(packet_v6), 0, (struct sockaddr *) (server_address->ai_addr),
                       server_address->ai_addrlen) == -1) {
                exit_error("Error: Couldn't send packet!\n");
            }

            //printf("Packet #%d \n", PACKETS_SENT);
            usleep(1000);
            memset(&packet_v6.data, 0, max_data_len);
        }
        // Neither IPv4 nor IPv6
        else {
            exit_error("Error: Invalid IP version of desired server!\n");
        }

    }
    printf("%d\n", PACKETS_SENT);
    return 0;
}

/**************************************
 *              MAIN                  *
 **************************************/
int main(int argc, char *argv[]) {
    // Determines whether the program is being executed as a client or server
    int LISTEN_MODE = 0;
    char *file = NULL;
    char *host = NULL;

    parse_arguments(argc, argv, &LISTEN_MODE, &file, &host);

    if (LISTEN_MODE) {
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
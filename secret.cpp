/**
 * @file secret.cpp
 * @author Filip Januska (xjanus11)
 *
 * Implementation of ISA project
 * FIT VUT 2021/2022
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <pcap.h>
#include <libgen.h>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <map>
#include <iostream>
#include <string>

/*****************************************************
 *      Macros, global variables and structures      *
 ****************************************************/

#define EXIT_SUCCESS 0
#define EXIT_ERROR 1

#define START_TRANSMISSION 31
#define END_TRANSMISSION 42

#define MAX_PACKET_SIZE 1500
// Size of the packet payload is rounded down to a multiple of 16
// "48" is the size of the "id" and "payload_len" members of the packet structure
#define MAX_PAYLOAD_LEN_IPV4 ( ( (MAX_PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr) - 48) / 16) * 16 )
#define MAX_PAYLOAD_LEN_IPV6 ( ( (MAX_PACKET_SIZE - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr) - 48) / 16) * 16)

// Contains pairs of <packet_id : encrypted_packet_data>
std::map<int, std::vector<char>> RECEIVE_BUFFER;
char *FILE_NAME = nullptr;
int PACKETS_SENT = 0;

// AES key
const unsigned char USER_KEY[] = "xjanus11";

typedef struct icmpv4_packet {
    struct icmphdr header;
    uint32_t id;
    uint16_t payload_len;
    char data[MAX_PAYLOAD_LEN_IPV4];
} icmpv4_packet;

typedef struct icmpv6_packet {
    struct icmp6_hdr header;
    uint32_t id;
    uint16_t payload_len;
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
void parse_arguments(int argc, char *argv[], int *LISTEN_MODE, char **file, char **host, int *delay) {
    int r_flag = 0;
    int s_flag = 0;
    int l_flag = 0;
    int d_flag = 0;
    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "r:s:ld:")) != -1) {
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
            case 'd':
                d_flag = 1;
                *delay = std::stoi(optarg);
                break;
            default:
                printf("usage: secret -r FILE -s SERVER [-l] [-d DELAY]\n");
                exit_error("Error; Unexpected argument!\n");
        }
    }
    //'-r' and '-s' options are required
    if (!l_flag && (!r_flag || !s_flag)) {
        printf("usage: secret -r FILE -s SERVER [-l] [-d DELAY]\n");
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
 * Saves the packet payload to the global map, holding all received data.
 * The map contains a pair of <packet_id : packet_payload> to ensure correct order of packets
 * @param data_size Size of the data
 * @param id Packet ID
 * @param payload Packet payload
 */
void save_payload(uint16_t data_size, uint32_t id, const char *payload) {
    std::vector<char> buff;
    buff.reserve(data_size);
    for (uint32_t i = 0; i < data_size; i++) {
        buff.push_back(payload[i]);
    }
    RECEIVE_BUFFER.insert({id, buff});
}

/**
 * Initializes the global variable holding the name of the received file
 * @param payload Name of the file - Null-terminated C string
 */
void init_filename(char *payload) {
    FILE_NAME = (char *) (calloc(1, strlen(payload)));
    if (FILE_NAME == nullptr) {
        exit_error("Error: Couldn't allocate server buffers!\n");
    }
    memcpy(FILE_NAME, basename(payload), strlen(basename(payload)));
}

/**
 * Takes the whole RECEIVE_BUFFER, decrypts the data using USER_KEY and saves it to an output file
 * @param difference Difference between the length of decrypted and encrypted data of the last packet
 * @param id Packet ID - important to identify the last packet
 * @param output Output file
 */
void decrypt_save_rec_buff(int difference, uint32_t id, std::ofstream &output) {
    AES_KEY dec_key;
    AES_set_decrypt_key(USER_KEY, 128, &dec_key);

    for (auto &data_block : RECEIVE_BUFFER) {
        // Iterate through the packet data blocks stored in RECEIVE_BUFFER

        // Holds the encrypted packet data in a string form
        std::string data_string(data_block.second.begin(), data_block.second.end());
        // Pointer to the data needed for pointer arithmetics
        char *data_raw = const_cast<char *>(data_string.c_str());
        for (int i = data_string.size(); i > 0; i -= 16) {
            // Iterate through the packet data in 16-sized steps
            // Since AES encrypts and decrypts 16 bytes at once
            int len = 16;
            char decrypted[16] = {};
            unsigned char encrypted[16] = {};

            if (id == data_block.first && i <= 16) {
                // Last block contains only (16 - difference) bytes of decrypted data
                len = 16 - difference;
            }
            memcpy(encrypted, data_raw + (data_string.size() - i), 16);
            AES_decrypt(encrypted, reinterpret_cast<unsigned char *>(decrypted), &dec_key);
            for (int j = 0; j < len; j++) {
                output << decrypted[j];
            }
        }
    }
}

/**
 * Analyzes a received packet
 * @param user Unused parameter
 * @param header Unused parameter
 * @param data Pointer to the beginning of the packet data
 */
void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {
    // Points to the beginning of the IP header.
    // Capturing on 'any' device causes pcap to replace a 14B ethernet header with a
    // 16B 'cooked header'. This skips the header and gets to the start of the IP header
    auto *iphdr_start = (uint8_t *) (data + 16);
    // Gets the first 8 bits of the IP header, applies a mask to extract
    // the first 4 bits ( 240d == 11110000b ) and shifts it to get the first
    // 4 bits as a number
    uint8_t protocol_version = (240 & *iphdr_start) >> 4;
    // Packet id
    uint32_t id = 0;
    // Length of !_DECRYPTED_! data of the packet
    uint16_t payload_len = 0;
    char *payload = nullptr;
    int packet_code = 0;
    int packet_type = 0;

    if (protocol_version == 4) {
        // IPv4 header
        auto *iphdr = (struct iphdr *) (data + 16);
        if (iphdr->protocol == 1) {
            // ICMP Protocol == 1

            // Pointer to the actual packet data. Skips the IP header
            auto *packet = (icmpv4_packet *) (((char *) iphdr) + sizeof(struct iphdr));
            id = packet->id;
            payload_len = packet->payload_len;
            payload = packet->data;
            packet_code = packet->header.code;
            packet_type = packet->header.type;
            if (packet_type != ICMP_ECHO) {
                return;
            }
        }
    } else if (protocol_version == 6) {
        // IPv6 header
        auto *ip6hdr = (struct ip6_hdr *) (data + 16);
        if (ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) {
            // ICMP6 protocol == 58

            // Pointer to the actual packet data. Skips the IPv6 header
            auto *packet = (icmpv6_packet *) (((char *) ip6hdr) + sizeof(struct ip6_hdr));
            id = packet->id;
            payload_len = packet->payload_len;
            payload = packet->data;
            packet_code = packet->header.icmp6_code;
            packet_type = packet->header.icmp6_type;
            if (packet_type != ICMP6_ECHO_REQUEST) {
                return;
            }
        }
    } else {
        return;
    }

    if (packet_code == START_TRANSMISSION) {
        // First packet of the transmission
        init_filename(payload);
    } else if (packet_code == END_TRANSMISSION) {
        // Last packet of the transmission

        // Last packet in reality usually contains more than "payload_len" bytes.
        // This is because the "payload_len" reports the size of the decrypted data, while the packet contains
        // encrypted data, size of which is always a multiple of 16
        // This rounds up the payload_len to nearest multiple of 16, ensuring that client reads the whole payload
        uint16_t padded_payload_len = ((payload_len) / 16) * 16 + 16;
        // This is the difference between the lenght of encrypted and decrypted data
        int difference = padded_payload_len - payload_len;

        save_payload(padded_payload_len, id, payload);

        // Open the output file
        std::ofstream output;
        output.open(FILE_NAME, std::ios::binary | std::ios::out);
        if (!output.is_open()) {
            exit_error("Error: Couldn't create output file!\n");
        }

        decrypt_save_rec_buff(difference, id, output);

        RECEIVE_BUFFER.clear();
        free(FILE_NAME);
        FILE_NAME = nullptr;
    } else {
        save_payload(payload_len, id, payload);
    }
}

/**
 * Represents the behavior of a server. Contains the main loop of the server
 */
void server() {
    pcap_t *device = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter{};

    device = pcap_open_live("any", 65535, 1, 1000, errbuf);
    if (device == nullptr) {
        fprintf(stderr, "Error: Pcap live open failed! [%s]\n", errbuf);
        exit(1);
    }

    if (pcap_compile(device, &filter, "icmp or icmp6", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        exit_error("Error: Couldn't compile filter!\n");
    }
    if (pcap_setfilter(device, &filter) == -1) {
        exit_error("Error: Couldn't apply filter!\n");
    }
    pcap_loop(device, -1, handle_packet, nullptr);
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
 * Encrypts a 16-sized data block
 * @param buff Source of the data
 * @param enc_key AES encryption key
 * @param encrypted Buffer to which the encrypted data is saved
 */
void encrypt_data_block(const char *buff, AES_KEY enc_key, unsigned char *encrypted) {
    char temp[16] = {};
    memcpy(temp, buff, 16);
    AES_encrypt(reinterpret_cast<const unsigned char *>(temp), encrypted, &enc_key);
}

/**
 * Prepares the Ipv4 packet for data transmission.
 * @param packet_v4 Ipv4 packet
 * @param file_size Size of the file to be sent
 * @param n_of_bytes Number of bytes of data from the input file, which this packet will hold
 * @param buff Buffer containing n_of_bytes bytes of data from the input file
 * @param encrypt Whether to encrypt the data or not
 * @return Prepared Ipv4 packet
 */
icmpv4_packet fill_packet_v4(icmpv4_packet packet_v4, size_t file_size, size_t n_of_bytes, const char *buff, bool encrypt) {

    // Contains the size of the current message
    packet_v4.payload_len = n_of_bytes;
    // Contains the ID of the packet
    packet_v4.id = PACKETS_SENT;

    // This packet is last to be sent - set the code accordingly, so the server knows communication is over
    if (file_size == 0) {
        packet_v4.header.code = END_TRANSMISSION;
    }

    // Encrypt the payload
    if (encrypt) {
        AES_KEY enc_key;
        AES_set_encrypt_key(USER_KEY, 128, &enc_key);
        for (int i = n_of_bytes; i > 0; i -= 16) {
            unsigned char encrypted[16] = {};
            encrypt_data_block(buff + (n_of_bytes - i), enc_key, encrypted);
            memcpy((packet_v4.data) + (n_of_bytes - i), encrypted, 16);
        }
    } else {
        memcpy(packet_v4.data, buff, n_of_bytes);
    }
    PACKETS_SENT++;
    return packet_v4;
}


/**
 * Prepares the Ipv6 packet for data transmission.
 * @param packet_v6 Ipv6 packet
 * @param file_size Size of the file to be sent
 * @param n_of_bytes Number of bytes of data from the input file, which this packet will hold
 * @param buff Buffer containing n_of_bytes bytes of data from the input file
 * @return Prepared Ipv6 packet
 */
icmpv6_packet fill_packet_v6(icmpv6_packet packet_v6, size_t file_size, size_t n_of_bytes,
                             const char *buff, bool encrypt) {
    // Contains the size of the current message
    packet_v6.payload_len = n_of_bytes;
    // Contains the ID of the packet
    packet_v6.id = PACKETS_SENT;

    // This packet is last to be sent - set the code accordingly, so the server knows communication is over
    if (file_size == 0) {
        packet_v6.header.icmp6_code = END_TRANSMISSION;
    }

    // Encrypt the payload
    if (encrypt) {
        AES_KEY enc_key;
        AES_set_encrypt_key(USER_KEY, 128, &enc_key);
        for (int i = n_of_bytes; i > 0; i -= 16) {
            unsigned char encrypted[16] = {};
            encrypt_data_block(buff + (n_of_bytes - i), enc_key, encrypted);
            memcpy((packet_v6.data) + (n_of_bytes - i), encrypted, 16);
        }
    } else {

        memcpy(packet_v6.data, buff, n_of_bytes);
    }
    PACKETS_SENT++;
    return packet_v6;
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
    for (; server_address != nullptr; server_address = server_address->ai_next) {
        int res = 0;
        if (server_address->ai_family == AF_INET) {
            // IPv4 address
            // First packet contains the file name and size of the whole file
            packet_v4 = fill_packet_v4(packet_v4, file_size, strlen(file), file, false);

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
            // First packet contains the file name and size of the whole file
            packet_v6 = fill_packet_v6(packet_v6, file_size, strlen(file), file, false);

            // Using the 'data32' field of the header to communicate the file size to server
            packet_v6.header.icmp6_dataun.icmp6_un_data32[0] = file_size;

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
 * Represents the behavior of a client
 * @param file Name of the input file
 * @param host Hostname/IP address of the server
 * @return Success
 */
void client(const char *file, const char *host, int send_delay) {
    struct addrinfo hints{};
    memset(&hints, 0, sizeof(struct addrinfo));
    // Support IPv4 and IPv6 addresses
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    struct addrinfo *server_address = nullptr;
    // Get the server IP address from entered hostname/IP
    if ((getaddrinfo(host, nullptr, &hints, &server_address)) != 0) {
        exit_error("Error: getaddrinfo() failed!\n");
    }

    // Create IPV4 and IPV6 sockets
    int sock_ipv4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sock_ipv6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock_ipv4 == -1 || sock_ipv6 == -1) {
        exit_error("Error: Couldn't create socket!\n");
    }

    // Prepare icmpv4 and icmpv6 packets. They contain an icmp header and
    // a data buffer
    // Depending on the server address from getaddrinfo(), icmpv4 or icmpv6 packet
    // will be used for the communication
    icmpv4_packet packet_v4{};
    initialize_icmpv4_packet(&packet_v4);

    icmpv6_packet packet_v6{};
    initialize_icmpv6_packet(&packet_v6);

    // Open the source file
    FILE *input_file = fopen(file, "rb");
    if (input_file == nullptr) {
        exit_error("Error: Couldn't open file!\n");
    }

    // Get the size of the file.
    size_t file_size = get_file_size(input_file);

    // Send the first packet, containing file name and file size
    server_address = send_meta_packet(file, server_address, sock_ipv4, sock_ipv6, packet_v4, packet_v6, file_size);

    if (server_address == nullptr) {
        exit_error("Error: Couldn't reach the server!\n");
    }

    // Number of bytes, which will be sent in the corresponding packet
    size_t n_of_bytes = 0;
    size_t max_data_len = (server_address->ai_family == AF_INET) ? MAX_PAYLOAD_LEN_IPV4 : MAX_PAYLOAD_LEN_IPV6;
    while (file_size > 0) {
        // Buffer which holds data from the file
        char buff[MAX_PACKET_SIZE] = {0};
        // Number of bytes to be sent. Normaly is equal to the maximum
        // In the last packet, number of bytes sent is the number of bytes left in the file
        n_of_bytes = (file_size > max_data_len) ? max_data_len : file_size;
        file_size -= n_of_bytes;

        // Read the required amount of bytes from input file
        if (fread(buff, 1, n_of_bytes, input_file) != n_of_bytes) {
            exit_error("Error reading file!\n");
        }

        // IPv4
        if (server_address->ai_family == AF_INET) {
            packet_v4 = fill_packet_v4(packet_v4, file_size, n_of_bytes, buff, true);
            if (sendto(sock_ipv4, &packet_v4, sizeof(packet_v4), 0, (struct sockaddr *) (server_address->ai_addr),
                       server_address->ai_addrlen) == -1) {
                exit_error("Error: Couldn't send packet!\n");
            }

            // Delay the next packet by (send_delay / 1000) ms, if -d parameter was specified. Default is 0
            // This helps if the server isn't able to catch all packets as they come too fast
            usleep(send_delay);
            memset(&packet_v4.data, 0, max_data_len);
        }
            // IPv6
        else if (server_address->ai_family == AF_INET6) {
            packet_v6 = fill_packet_v6(packet_v6, file_size, n_of_bytes, buff, true);
            if (sendto(sock_ipv6, &packet_v6, sizeof(packet_v6), 0, (struct sockaddr *) (server_address->ai_addr),
                       server_address->ai_addrlen) == -1) {
                exit_error("Error: Couldn't send packet!\n");
            }

            // Delay the next packet by (send_delay / 1000) ms, if -d parameter was specified. Default is 0
            // This helps if the server isn't able to catch all packets as they come too fast
            usleep(send_delay);
            memset(&packet_v6.data, 0, max_data_len);
        }
    }
    fclose(input_file);
}

/**************************************
 *              MAIN                  *
 **************************************/
int main(int argc, char *argv[]) {
    // Determines whether the program is being executed as a client or server
    int LISTEN_MODE = 0;
    char *file = nullptr;
    char *host = nullptr;
    int send_delay = 0;

    parse_arguments(argc, argv, &LISTEN_MODE, &file, &host, &send_delay);

    if (LISTEN_MODE) {
        server();
        return EXIT_SUCCESS;
    }

    client(file, host, send_delay);
    return EXIT_SUCCESS;
}
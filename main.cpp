#include <stdio.h>
#include <netdb.h>	   // getaddrinfo
#include <string.h>	   //memset
#include <arpa/inet.h> // inet_ntop
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <stdlib.h>

//yonikol
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char **argv)
{
	struct addrinfo hints, *serverinfo;
	memset(&hints, 0, sizeof(hints));

	char *host = "google.sk";
	int result;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;

	if ((result = getaddrinfo(host, NULL, &hints, &serverinfo)) != 0)
	{
		fprintf(stderr, "%s\n", gai_strerror(result));
		return 1;
	}

	char ip[100];
	inet_ntop(serverinfo->ai_family, get_in_addr(serverinfo->ai_addr), ip, 100);
	printf("ip: %s\n", ip);

	int protocol = serverinfo->ai_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;

	int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
	if (sock == -1)
	{
		fprintf(stderr, "sock err :)\n");
		return 1;
	}

	char packet[1500];
	char data[] = "Monntegea";
	int datalen = 10;

	memset(&packet, 0, 1500);

	struct icmphdr *icmp_header = (struct icmphdr *)packet;
	icmp_header->code = ICMP_ECHO;
	icmp_header->checksum = 0;
	//vypočitaj si checksum ak chceš :)

	memcpy(packet + sizeof(struct icmphdr), data, datalen);

	// MAXDATALEN = MTU(1500B) - zvyšna velkost čo si spotreboval :)

	if (sendto(sock, packet, sizeof(struct icmphdr) + datalen, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
	{
		fprintf(stderr, "sendto err :)\n");
		return 1;
	}

	// //šifrovanie

	const unsigned char cyphertext[] = "Monntegea";
	int cyphertextlen = 10;

	AES_KEY key_e;
	AES_KEY key_d;
	AES_set_encrypt_key((const unsigned char *)"xlogin00", 128, &key_e);
	AES_set_decrypt_key((const unsigned char *)"xlogin00", 128, &key_d);

	unsigned char *output = (unsigned char *)calloc(cyphertextlen + (AES_BLOCK_SIZE % cyphertextlen), 1);

	AES_encrypt(cyphertext, output, &key_e);

	printf("encrypted: ");
	for (int i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		printf("%X ", output[i]);
	}
	printf("\n");

	AES_decrypt(output, output, &key_d);

	printf("decrypted: %s\n", output);

	return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>

#define EXIT_SUCCESS 0
#define EXIT_ERROR 1

void exit_error(const char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(EXIT_ERROR);
}


int main(int argc, char*argv[])
{
    // Determines whether the program is being executed as a client or server
    int LISTEN_MODE = 0;

    /*                  *
     * Argument parsing *
     *                  */

    int r_flag = 0;
    int s_flag = 0;
    int l_flag = 0;

    char * file = NULL;
    char * host = NULL;

    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "r:s:l")) != -1)
    {
        switch (c)
        {
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
    if (l_flag && (r_flag || s_flag))
    {
        exit_error("Error: '-l'  option can't be used in combination with other options!\n");
    }


    // '-r' and '-s' options are required
    if (!l_flag && (!r_flag || !s_flag))
    {
        exit_error("Error: Missing arguments!\n");
    }

    LISTEN_MODE = l_flag;

    struct addrinfo hints;
    struct addrinfo *root = NULL;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    if ((getaddrinfo(host, NULL, &hints, &root)) != 0)
    {
        exit_error("Error: getaddrinfo() failed!\n");
    }

    while (root != NULL) {
        char ip[100];
        inet_ntop(root->ai_family, &(((struct sockaddr_in *) root->ai_addr)->sin_addr), ip, 100);
        printf("ip: %s\n", ip);
        root = root->ai_next;
    }
    return 0;
}
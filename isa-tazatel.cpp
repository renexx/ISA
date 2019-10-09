/*
 *      ISA 2019
 *      WHOIS tazatel - autor zadania Ing. Veselý
 *      vypracoval - René Bolf (xbolfr00@vutbr.cz)
 *
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h> // getopt
//#include <getopt.h> // for getopt_long
#define BUFFER 1024
void print_usage()
{
    printf("-q<IP|hostname>, povinny argument\n");
    printf("-w <IP|hostname> WHOIS serveru>, ktorý bude dotazovaný povinný argument\n");
    printf("-d <IP|hostname DNS serveru>, ktorý bude dotazovaný, nepovinny argument pričom implicitne sa bere 1.1.1.1\n");
    exit(2);
}
int main(int argc, char **argv) {
    int option;
    int client_socket, port_number, bytenasend, byteread;
    socklen_t len;
    const char *hostname, *addr;
    struct hostent *hostent;
    struct servent *servent;
    struct sockaddr_in server_address;
    char buf[BUFFER];

    if (argc < 2)
    {
        fprintf(stderr, "ERROR: Nebol zadany ziadny argument\n");
        print_usage();
        return -1;
    }
    hostname = argv[1];
    port_number = atoi(argv[2]);
     /* 2. ziskani adresy serveru pomoci DNS  ziska IP adresu z domeny dotazuje sa na DNS zaznam A*/
    if ((hostent = gethostbyname(hostname)) == NULL){
        fprintf(stderr, "Error: no such host as %s\n", hostname);
        exit(EXIT_FAILURE);
    }
    /*preklad z ip na domenu*/
    /*if ((hostent = gethostbyaddr(addr,len, AF_INET)) == NULL)
    {
        fprintf(stderr, "Error: no such host asaaa %s\n", hostname);
        exit(EXIT_FAILURE);
    }*/
    /* 3. nalezeni IP adresy serveru a inicializace struktury server_address */
     /*bzero((char *) &server_address, sizeof(server_address));
     server_address.sin_family = AF_INET;
     bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
     */
     memset(&server_address,0,sizeof(server_address));  //nastavy dany pocet bytov na hodnotu uvedenu v parametri c
     server_address.sin_family = AF_INET; /* IPV4*/
     memcpy(&server_address.sin_addr,hostent->h_addr,hostent->h_length); // porovnava retazec bytov , kopiruje specifikovany pocet bytov do cielovej struktury
     server_address.sin_port = htons(port_number); /*host to network byte order short*/

     /* tiskne informace o vzdalenem soketu */
    printf("INFO: Server socket: %s : %d \n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));

    /* Vytvoreni soketu a inicializovanie soketu*/
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) /*AF_INET = IPv4, SOCK_STREAM = TCP, 0 je protokol 0 implicitne vybere podla SOCK_STREAM, inak IPPROTO_TCP*/
    {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }
    /*Aktivne otvorenie na strane klienta, druhy parameter funkcie obsahuje ip adresu a port servera*/
    if (connect(client_socket, (const struct sockaddr *) &server_address, sizeof(server_address)) != 0)
    {
        perror("ERROR: connect");
        exit(EXIT_FAILURE);
    }
    /* odeslani zpravy na server */
    bytenasend = send(client_socket, buf, strlen(buf), 0);
    if (bytenasend < 0)
    perror("ERROR in sendto");


    /* prijeti odpovedi a jeji vypsani */
    byteread = recv(client_socket, buf, BUFFER, 0);
    if (byteread < 0)
        perror("ERROR in recvfrom");

    printf("Echo from server: %s\n", buf);
    //service(STDIN_FILEN0, client_socket);

    close(client_socket);
    /*
    while ((option = getopt(argc, argv, "q:w:d:")) != -1){
        switch (option) {
            case 'q':
                    printf("IP or hostname\n");
                    break;
            case 'w':
                    printf("IP or hostname WHOIS serveru\n");
                    break;
            case 'd':
                    printf("IP or hostnaem DNS serveru\n");
                    break;
            case '?':
                    printf("Unknown option: %c\n", optopt);
                    break;
            case ':':
                    printf("Missing arg for %c\n", optopt);
                    break;
            default:
                    printf("Error spatne zadane arumenty\n");
                    print_usage();


        }
    }*/ //**tu je getopts*/


    return 0;
}

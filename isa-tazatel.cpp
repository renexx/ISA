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
#include<err.h>
#include <string>
using namespace std;    // Or using std::string;
//#include <getopt.h> // for getopt_long
#define BUFFER 65535
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
    const char *addr;
    struct hostent *hostent, *he;
    struct servent *servent;
    struct sockaddr_in server_address, klient_adress;
    extern char *optarg;
    bool q_flag = false;
    bool w_flag = false;
    bool d_flag = false;
    char hostname[100], whois[100], dns[100];
    char buf[BUFFER];
    int msg_size;

    while ((option = getopt(argc, argv, "q:w:d:")) != -1){
       switch (option) {
           case 'q':
                   if(q_flag == false)
                   {
                       strcpy(hostname,optarg);
                   }
                   else
                   {
                       fprintf(stderr, "Chyba q_flag je povinny\n");
                       print_usage();
                   }
                   break;
           case 'w':
                   if(w_flag == false)
                   {
                       strcpy(whois,optarg);
                   }
                   else
                   {
                       fprintf(stderr, "Chyba w_flag je povinny\n");
                       print_usage();
                   }
                   break;
           case 'd':

                    strcpy(dns,optarg);
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
   }

     /* 2. ziskani adresy serveru pomoci DNS  ziska IP adresu z domeny dotazuje sa na DNS zaznam A*/

    if ((hostent = gethostbyname(whois)) == NULL){
        fprintf(stderr, "Error: no such host as %s\n", whois);
        exit(EXIT_FAILURE);
    }
     printf("\nWHOIS SERVER  \t: \t%s\n",whois);

     memset(&server_address,0,sizeof(server_address));  //nastavy dany pocet bytov na hodnotu uvedenu v parametri c
     server_address.sin_family = AF_INET; /* IPV4*/
     memcpy(&server_address.sin_addr,hostent->h_addr,hostent->h_length); // porovnava retazec bytov , kopiruje specifikovany pocet bytov do cielovej struktury
     server_address.sin_port = htons(43); /*host to network byte order short*/
     printf("SERVER ADRESS \t: \t%s \n", inet_ntoa(server_address.sin_addr)); // ten co zadam ako argument


    if ((he = gethostbyname(hostname)) == NULL){
        fprintf(stderr, "Error: no such host as %s\n", hostname);
        exit(EXIT_FAILURE);
    }
     printf("CLIENT ADRESS \t: \t%s\n",hostname);
     memset(&klient_adress,0,sizeof(klient_adress));  //nastavy dany pocet bytov na hodnotu uvedenu v parametri c
     klient_adress.sin_family = AF_INET; /* IPV4*/
     memcpy(&klient_adress.sin_addr,he->h_addr,he->h_length); // porovnava retazec bytov , kopiruje specifikovany pocet bytov do cielovej struktury
     printf("CLIENT ADRESS \t: \t%s \n", inet_ntoa(klient_adress.sin_addr));
     char *daco = (char*)malloc(sizeof(char) * 1024);
     strcpy(daco,inet_ntoa(klient_adress.sin_addr));
     printf("hahaha %s\n",daco);
    /* Vytvoreni soketu a inicializovanie soketu*/
    if ((client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0) /*AF_INET = IPv4, SOCK_STREAM = TCP, 0 je protokol 0 implicitne vybere podla SOCK_STREAM, inak IPPROTO_TCP*/
    {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("SOcket vytvoreny\n");
    }
    /*Aktivne otvorenie na strane klienta, druhy parameter funkcie obsahuje ip adresu a port servera*/
    if (connect(client_socket, (const struct sockaddr *) &server_address, sizeof(server_address)) != 0)
    {
        perror("ERROR: connect");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Si pripojeny\n");


    }
    /* odeslani zpravy na server */

    
    bytenasend = send(client_socket, buf, strlen(buf), 0);
    if (bytenasend < 0)
    {
        perror("ERROR in sendto\n");

    }
    else
    {
        printf("hahaha juuu %s\n",daco);
        printf("Poslalo sa\n");

    }

// I have this block of code from example , author is Mr. Matouska
    if ((byteread = read(client_socket,buf,BUFFER)) == -1){  // read an initial string
        err(1,"initial read() failed");
    } else {
        printf("%.*s\n",byteread,buf);
    }
    while((msg_size=read(STDIN_FILENO,buf,BUFFER)) > 0)
  {
    byteread = write(client_socket,buf,msg_size);             // send data to the server
    if (byteread == -1)                                 // check if data was sent correctly
      err(1,"write() failed");
    else if (byteread != msg_size)
      err(1,"write(): buffer written partially");

    if ((byteread = read(client_socket,buf, BUFFER)) == -1)   // read the answer from the server
      err(1,"read() failed");
    else if (byteread > 0)
      printf("%.*s",byteread,buf);

  }

  if (msg_size == -1)
    err(1,"reading failed");

/*
  while(byteread = recv(client_socket, buf, BUFFER, 0))
  {


  if (byteread < 0)
  perror("ERROR in recvfrom");

  printf("Echo from server: %s\n", buf);
  //service(STDIN_FILEN0, client_socket);
}*/
   close(client_socket);
   printf("* Closing client socket ...\n");
   free(daco);
  return 0;
}

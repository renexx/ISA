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
#include <iostream>
#include <regex>
#include <arpa/nameser.h>

#include <resolv.h>

using namespace std;    // Or using std::string;
//#include <getopt.h> // for getopt_long
#define BUFFER 65535
#define N 4096
void print_usage()
{
    printf("-q<IP|hostname>, povinny argument\n");
    printf("-w <IP|hostname> WHOIS serveru>, ktorý bude dotazovaný povinný argument\n");
    printf("-d <IP|hostname DNS serveru>, ktorý bude dotazovaný, nepovinny argument pričom implicitne sa bere 1.1.1.1\n");
    exit(2);
}

void PrintRegexMatch(std::string str, std::regex reg)
{
    std::smatch match;
    //std::cout << std::boolalpha;
    while(std::regex_search(str,match,reg))
    {

        std::cout << match.str() << "\n";
        str = match.suffix().str();

    }
}

int main(int argc, char **argv) {
    int option;
    int client_socket, port_number, bytenasend, byteread;
    socklen_t len;
    const char *addr;
    struct hostent *hostent, *he;
    struct servent *servent;
    struct sockaddr_in server_address, klient_adress;
    struct sockaddr_in6 ipv6;
    extern char *optarg;
    bool q_flag = false;
    bool w_flag = false;
    bool d_flag = false;
    char hostname[100], whois[100], dns[100];
    char buf[BUFFER];
    int msg_size;
    int i = 0;
    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;
    int x, l;



    string input;
    std::regex inetnumReg("inetnum:.*");
    std::regex netnameReg("netname:.*");
    std::regex descrReg("descr:.*");
    std::regex countryReg("country:.*");
    std::regex addressReg("address:.*");
    std::regex phoneReg("phone:.*");
    std::regex admin_cReg("admin-c:.*");
//    std::cmatch m;

    if(argc < 5 || argc > 7)
    {
        fprintf(stderr, "Error arguments\n");
        print_usage();
    }
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

     // HEADER
        cout << "======== DNS:\t" << dns << "=============\n";
 // -----
        l = res_query(hostname,ns_c_any,ns_t_aaaa,nsbuf,sizeof(nsbuf));
        if(l < 0)
        {
            perror(hostname);
        }
        ns_initparse(nsbuf,l,&msg);
        //l= ns_msg_count(msg,ns_s_an);
        ns_parserr(&msg, ns_s_an, i, &rr);
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        printf("%s \n", dispbuf);


        l = res_query(hostname,ns_c_any,ns_t_a,nsbuf,sizeof(nsbuf));
        if(l < 0)
        {
            perror(hostname);
        }
        ns_initparse(nsbuf,l,&msg);
        //l= ns_msg_count(msg,ns_s_an);
        ns_parserr(&msg, ns_s_an, i, &rr);
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        printf("\n%s \n", dispbuf);

        l = res_query(hostname,ns_c_any,ns_t_mx,nsbuf,sizeof(nsbuf));
        if(l < 0)
        {
            perror(hostname);
        }
        ns_initparse(nsbuf,l,&msg);
        //l= ns_msg_count(msg,ns_s_an);
        ns_parserr(&msg, ns_s_an, i, &rr);
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        printf("%s \n", dispbuf);

        l = res_query(hostname,ns_c_any,ns_t_cname,nsbuf,sizeof(nsbuf));
        if(l < 0)
        {
            perror(hostname);
        }
        ns_initparse(nsbuf,l,&msg);
        //l= ns_msg_count(msg,ns_s_an);
        ns_parserr(&msg, ns_s_an, i, &rr);
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        printf("toto je cname%s, a toto je name %s \n", dispbuf, ns_rr_name());

        /*printf("NS:");
           l = res_query(hostname, ns_c_any, ns_t_ns, nsbuf, sizeof(nsbuf));
           if (l < 0)
           {
             perror(hostname);
           }
           ns_initparse(nsbuf, l, &msg);
           l = ns_msg_count(msg, ns_s_an);

           ns_parserr(&msg, ns_s_an, 0, &rr);
           ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
           printf("%s \n", dispbuf);
*/




    // printf("A: \t%s \n", inet_ntoa(klient_adress.sin_addr));

     //printf("CNAME: %s\n",he->h_name);

     char *daco = (char*)malloc(sizeof(char) * 1024);
     strcpy(daco,inet_ntoa(klient_adress.sin_addr));

     memset(&ipv6,0,sizeof(ipv6));  //nastavy dany pocet bytov na hodnotu uvedenu v parametri c
     ipv6.sin6_family = AF_INET6; /* IPV4*/
     memcpy(&ipv6.sin6_addr,he->h_addr,he->h_length); // porovnava retazec bytov , kopiruje specifikovany pocet bytov do cielovej struktury
//     inet_pton(AF_INET6, hostname, &(ipv6.sin6_addr));

     char str[INET6_ADDRSTRLEN];

    // str = hostname;
     inet_ntop(AF_INET6,&ipv6.sin6_addr,str,sizeof(str));
    // cout << "AAAA:\t" <<str << "\n";


    /* Vytvoreni soketu a inicializovanie soketu*/
    if ((client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0) /*AF_INET = IPv4, SOCK_STREAM = TCP, 0 je protokol 0 implicitne vybere podla SOCK_STREAM, inak IPPROTO_TCP*/
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

    strcat(daco,"\n");
    strcpy(buf,daco);
    while(i < 2)
     {
        /* code */
        bytenasend = send(client_socket, buf, strlen(buf), 0);
        if (bytenasend < 0)
        {
            perror("ERROR in sendto\n");
        }

    // I have this block of code from example , author is Mr. Matouska
        if ((byteread = read(client_socket,buf,BUFFER)) == -1){  // read an initial string
            err(1,"initial read() failed");
        } else {

        }
        i++;
    }

    //    printf("%.*s\n",byteread,buf);
        input = buf;

        cout << "====== WHOIS ===========\n";
        PrintRegexMatch(input,inetnumReg);
        PrintRegexMatch(input,netnameReg);
        PrintRegexMatch(input,descrReg);
        PrintRegexMatch(input,countryReg);
        PrintRegexMatch(input,admin_cReg);
        PrintRegexMatch(input,addressReg);
        PrintRegexMatch(input,phoneReg);

   close(client_socket);
   printf("\n\n* Closing client socket ...\n");
   free(daco);
  return 0;
}

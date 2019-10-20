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
#define lanswer 4096
#define ldname  65535
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
std::string getHostname(const char *domName)
{
    struct sockaddr_in server_address, klient_adress;
    memset(&klient_adress, 0, sizeof klient_adress);
    klient_adress.sin_family = AF_INET;
    char domain_name[100];
    strcpy(domain_name,domName);
    memset(&klient_adress, 0, sizeof klient_adress);
    klient_adress.sin_family = AF_INET;


    inet_pton(AF_INET, domain_name, &klient_adress.sin_addr);

    int result = getnameinfo((struct sockaddr*)&klient_adress,sizeof(klient_adress),domain_name,sizeof(domain_name),NULL,0,NI_NAMEREQD);
    if(result)
    {
        fprintf(stderr, "65 vo funkci getHostname %s: %s\n", domain_name, gai_strerror(result));

    //    exit(EXIT_FAILURE); TU JE ODSTREANENY EXIT LEBO TO POTOM NEFUNGUJE AK ZADAS domenu
    }
    else
    {

        printf("DOMAIN NAME: %s\n", domain_name);    // e.g. "www.example.com"
    }
    std::string ip;
    ip += domain_name;
    return ip;

}
void runDnsQuery(const char *dname, int nType)
{

    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;

    int x = 0, l;
    int msg_size;


    std::regex a_dns("A.*");
    std::regex aaaa_dns("AAAA.*");
    std::regex soa_dns("SOA.*");
    std::regex mx_dns("MX.*");
    std::regex ns_dns("NS.*");
    std::regex ptr_dns("A.*");
    std::regex cname_dns("CNAME.*");
// HEADER

    l = res_search(dname,ns_c_any,nType,nsbuf,sizeof(nsbuf));
    if(l < 0)
    {
        perror("kurva 103");
    }
    ns_initparse(nsbuf,l,&msg);
    //l= ns_msg_count(msg,ns_s_an);
    ns_parserr(&msg, ns_s_an, x, &rr);
    ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
    printf("%s \n", dispbuf);
/*    PrintRegexMatch(dispbuf,a_dns);
    PrintRegexMatch(dispbuf,mx_dns);
    PrintRegexMatch(dispbuf,soa_dns);
    PrintRegexMatch(dispbuf,ns_dns);
    PrintRegexMatch(dispbuf,ptr_dns);
    PrintRegexMatch(dispbuf,cname_dns);*/




    // return 0;
}

int main(int argc, char **argv) {
    int option;
    int client_socket, port_number, bytenasend, byteread;
    socklen_t len;
    const char *addr;

    struct servent *servent;

    struct sockaddr_in6 ipv6;
    extern char *optarg;
    bool q_flag = false;
    bool w_flag = false;
    bool d_flag = false;
    char hostname[100], whois[100], dns[100];

    char buf[BUFFER];

    int i = 0;
    int msg_size;
    struct addrinfo whois_server, *whois_infoptr, *whois_ptr, client_adress, *client_infoptr, *client_ptr;
    int result_for_whois, result_for_client;

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

cout << "======== DNS:\t" << dns << "=============\n";


    std::string result = getHostname(hostname);

    const char *ip = result.c_str();
    cout << "TOTO JE SOA \n";
    runDnsQuery(ip,ns_t_soa);

    cout << "\nTOTO JE AAAAA \n";
    runDnsQuery(ip,ns_t_aaaa);
    cout << "\nTOTO JE A \n";
    runDnsQuery(ip,ns_t_a);
    cout << "HLUPAAAK" << ip;




    cout <<"KDE SOM" << ip;
    cout << "\nTOTO JE PTR \n";
    runDnsQuery(ip,ns_t_ptr);
    cout << "\nTOTO JE CNAME \n";
    runDnsQuery(ip,ns_t_cname);
    cout << "\nTOTO JE NS \n";
    runDnsQuery(ip,ns_t_ns);
    cout << "\nTOTO JE MX \n";
    runDnsQuery(ip,ns_t_mx);




     /* 2. ziskani adresy serveru pomoci DNS  ziska IP adresu z domeny dotazuje sa na DNS zaznam A*/

     memset(&whois_server,0,sizeof(whois_server));  //nastavy dany pocet bytov na hodnotu uvedenu v parametri c
     whois_server.ai_family = AF_INET;
     whois_server.ai_socktype = SOCK_STREAM;
     whois_server.ai_protocol = IPPROTO_TCP;

     result_for_whois = getaddrinfo(whois,"43",&whois_server,&whois_infoptr);
     if(result_for_whois != 0)
     {
         fprintf(stderr, "%s: %s\n", whois, gai_strerror(result_for_whois));
         exit(EXIT_FAILURE);
     }

     for(whois_ptr = whois_infoptr; whois_ptr != NULL; whois_ptr = whois_ptr->ai_next)
     {
         getnameinfo(whois_ptr->ai_addr,whois_ptr->ai_addrlen,whois,sizeof(whois),NULL,0,NI_NUMERICHOST);
         /* Vytvoreni soketu a inicializovanie soketu*/
         if ((client_socket = socket(whois_infoptr->ai_family, whois_infoptr->ai_socktype, whois_infoptr->ai_protocol)) <= 0) /*AF_INET = IPv4, SOCK_STREAM = TCP, 0 je protokol 0 implicitne vybere podla SOCK_STREAM, inak IPPROTO_TCP*/
         {
             perror("ERROR 224: socket");
             exit(EXIT_FAILURE);
         }

         /*Aktivne otvorenie na strane klienta, druhy parameter funkcie obsahuje ip adresu a port servera*/
         if (connect(client_socket, whois_ptr->ai_addr, whois_ptr->ai_addrlen) != 0)
         {
             perror("ERROR 231: connect");
             exit(EXIT_FAILURE);
         }
     }
     cout <<"WHOIS IP ADDRESS:\t " << whois << "\n";

     memset(&client_adress,0,sizeof(client_adress));
     client_adress.ai_family = AF_INET;
     client_adress.ai_socktype = SOCK_STREAM;
     client_adress.ai_protocol = IPPROTO_TCP;

     result_for_client = getaddrinfo(hostname,NULL,&client_adress,&client_infoptr);
     if(result_for_client != 0)
     {
         fprintf(stderr, "%s: %s\n", hostname, gai_strerror(result_for_client));
         exit(EXIT_FAILURE);
     }
     for(client_ptr = client_infoptr; client_ptr != NULL; client_ptr = client_ptr->ai_next)
     {
         getnameinfo(client_ptr->ai_addr,client_ptr->ai_addrlen,hostname,sizeof(hostname),NULL,0,NI_NUMERICHOST);

     }
    /* inet_pton(AF_INET, hostname, &klient_adress);
     he = gethostbyaddr(&klient_adress, sizeof(klient_adress),AF_INET);
     printf("Host name: %s\n", he->h_name);*/
     getHostname(hostname);
     getHostname(whois);
    /* odeslani zpravy na server */


    strcpy(buf,hostname);
    strcat(buf,"\r\n");//<CR><LF>
    cout << buf;

    bytenasend = send(client_socket, buf, strlen(buf),0);
    if (bytenasend == -1)
    {
        perror("ERROR in sendto 270\n");
    }

    // I have this block of code from example , author is Mr. Matouska
    if ((bytenasend = recv(client_socket,buf,BUFFER,MSG_WAITALL)) == -1){  // MSG_WAITALL pri čitani sa čaká na všetky data
        err(1,"initial read() failed");
    }

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
   //free(daco);
   freeaddrinfo(whois_infoptr);
   freeaddrinfo(client_infoptr);
   return 0;
}

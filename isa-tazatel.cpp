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

int PrintRegexMatch(std::string str, std::regex reg)
{
    std::smatch match;
    int counter = 0;
    //std::cout << std::boolalpha;
    while(std::regex_search(str,match,reg))
    {
        std::cout << match.str() << "\n";
        str = match.suffix().str();
      //  cout<<"TOTO JE MATCH"<< match[2];
      counter++;
    }
    return counter;
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
/*    if(result)
    {
        fprintf(stderr, "65 vo funkci getHostname %s: %s\n", domain_name, gai_strerror(result));
    //    exit(EXIT_FAILURE); TU JE ODSTREANENY EXIT LEBO TO POTOM NEFUNGUJE AK ZADAS domenu
}*/



    //printf("DOMAIN NAME: %s\n\n\n", domain_name);    // e.g. "www.example.com"

    std::string ip;
    ip += domain_name;


    return ip;

}
std::string runDnsQuery(const char *dname, int nType)
{

    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;

    int x, l;
    int msg_size;


    std::regex a_dns("(\\sA)(.+[[:digit:]])\\.(.+)");
    std::regex aaaa_dns("(AAAA)(.+)");

    std::regex mx_dns("MX.+[a-zA-Z]");
    std::regex ns_dns("NS.+\\S");
    std::regex ptr_dns("\\sPTR.*");
    std::regex cname_dns("CNAME.*");
// HEADER
    std::cmatch m;
    l = res_search(dname,ns_c_any,nType,nsbuf,sizeof(nsbuf));
    //if(l < 0)
    //{
      //  perror("d");
    //}
    ns_initparse(nsbuf,l,&msg);
    l= ns_msg_count(msg,ns_s_an);
    for(x = 0; x < l; x++)
    {
        ns_parserr(&msg, ns_s_an, x, &rr);
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
    // /
      //  cout <<"AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

      //  printf("%s \n", dispbuf);


        PrintRegexMatch(dispbuf,ns_dns);
        PrintRegexMatch(dispbuf,aaaa_dns);
        PrintRegexMatch(dispbuf,cname_dns);
      //  PrintRegexMatch(dispbuf,a_dns);
        //if(daco == 0){
          //cout << "nebolo najdene a\n";
        //}
        PrintRegexMatch(dispbuf,mx_dns);

        PrintRegexMatch(dispbuf,ptr_dns);


    }

    std::string vypis;
    vypis += dispbuf;
    return vypis;

}
std::string  resolvePtr(const char* dname)
{
  in_addr_t addr4;
  register int i;
  int ipAddr[4] = {0,0,0,0};
  char buf[N];
  std::string nRet;
  if((addr4 = inet_network(dname)) != -1){
    for(i = 0; addr4; ){
      ipAddr[i++] = addr4 & 0xFF;
      addr4 >>= 8;

    }
    sprintf(buf,"%u.%u.%u.%u.in-addr.arpa",ipAddr[i % 4], ipAddr[(i+1) % 4], ipAddr[(i+2) % 4], ipAddr[(i+3) % 4]);
    nRet = runDnsQuery(buf,ns_t_ptr);
    //cout << buf;
    cout << nRet<<"\n";

  }
/*  else{

    runDnsQuery(dname,ns_t_a);
    nRet = runDnsQuery(dname,ns_t_mx);
    cout <<"AAAAAAAAAAAAAAAAAAAAAAAAAa"<< nRet <<"\n";
  }
*/


  return nRet;


}

int main(int argc, char **argv) {
    int option;
    int client_socket, port_number, bytenasend, byteread;
    socklen_t len;
    const char *addr;

    struct servent *servent;
    struct hostent *hostent_dns;
    struct sockaddr_in dns_ad;
    extern char *optarg;
    bool q_flag = false;
    bool w_flag = false;
    bool d_flag = false;
    char hostname[100], whois[100], dns[100];

    char buf[BUFFER];

    int i = 0;
    int msg_size;
    struct addrinfo whois_server, *whois_infoptr, *whois_ptr, client_adress, *client_infoptr, *client_ptr;
    struct addrinfo dns_adress, *dns_infoptr, *dns_ptr;
    int result_for_whois, result_for_client,result_for_dns;

    string input;
    std::regex inetnumReg("(inetnum:.*|netrange:.*|nethandle:.*)",std::regex_constants::icase);
    std::regex netnameReg("netname:.*",std::regex_constants::icase);
    std::regex descrReg("(descr:.*|organization:.*)",std::regex_constants::icase);
    std::regex countryReg("country:.*",std::regex_constants::icase);
    std::regex addressReg("address:.*",std::regex_constants::icase);
    std::regex phoneReg("phone:.*");
    std::regex admin_cReg("admin-c:.*",std::regex_constants::icase);

    /* REGEX FOR WHOIS.ARIN.NET */
    std::regex cidrReg("CIDR:.*",std::regex_constants::icase);
    std::regex rtechPhoneReg("RTechPhone:.*",std::regex_constants::icase);
    std::regex orgtechPhoneReg("OrgTechPhone:.*",std::regex_constants::icase);
    std::regex orgAbusePhoneReg("OrgAbusePhone:.*",std::regex_constants::icase);


    /*------------- REGEX FOR WHOIS.NIC.CZ--------------*/
  /*  std::regex domianReg("domain:.*",std::regex_constants::icase);
    std::regex registrantReg("registrant:.*",std::regex_constants::icase);
    std::regex registrarReg("registrar:.*",std::regex_constants::icase);
    std::regex orgReg("org:.*",std::regex_constants::icase);
    std::regex nameReg("name:.*",std::regex_constants::icase);
    std::regex contactReg("contact:.*",std::regex_constants::icase);
    std::regex nserverReg("nserver:.*",std::regex_constants::icase);*/

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
                    d_flag = true;
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

cout << "======== DNS =========== "<<"\n";

/*
      if(d_flag == true)
      {
        char buf[16];
        memset(&dns_adress,0,sizeof(dns_adress));
      //  if (inet_pton(AF_INET, dns, /*&_res.nsaddr_list[0].sin_addr*///buf))
      //  {
        //  res_init();
        /*  result_for_dns = getaddrinfo(dns,NULL,&dns_adress,&dns_infoptr);
          if(result_for_dns != 0)
          {
              fprintf(stderr, "%s: %s\n", dns, gai_strerror(result_for_dns));
              exit(EXIT_FAILURE);
          }
          for(dns_ptr = dns_infoptr; dns_ptr != NULL; dns_ptr = dns_ptr->ai_next)
          {
              getnameinfo(dns_ptr->ai_addr,dns_ptr->ai_addrlen,dns,sizeof(dns),NULL,0,NI_NUMERICHOST);
          }
          strcpy(&_res.nsaddr_list[0].sin_addr,dns_ptr->ai_addr);
          cout <<dns_addr->h_addr_list[0];
          _res.nscount = 1;*/
      /*    if ((hostent_dns = gethostbyname(dns)) == NULL) {
              fprintf(stderr,"ERROR: no such host as %s\n", dns);
              exit(EXIT_FAILURE);
            }
        //  int dns_port_number = 53;
        //  bzero((char *) &dns_ad, sizeof(dns_ad));
      //  dns_ad.sin_family = AF_INET;
        //  dns_ad.sin_port = htons(dns_port_number);
        //  bcopy((char *)hostent_dns->h_addr, (char *)&dns_ad.sin_addr.s_addr, hostent_dns->h_length);
          (void)memcpy((void*)&_res.nsaddr_list[0].sin_addr,(void*)hostent_dns->h_addr_list[0],(size_t)hostent_dns->h_length);
          _res.nscount = 1;
        }
        else
        {
          fprintf(stderr, "NO IP addres as %s\n",dns);
          exit(EXIT_FAILURE);
        }
      }*/

    std::string result = getHostname(hostname);

    std::string orezane = result;
    std::size_t pos = orezane.find(".");
    std:string str3 = orezane.substr(pos + 1);

    const char *domenove_meno = result.c_str(); //www.mobilmania.cz
    const char *domain = str3.c_str(); //mobilmania.cz
    resolvePtr(hostname);
    runDnsQuery(domenove_meno,ns_t_aaaa);
    runDnsQuery(domenove_meno,ns_t_a);
    runDnsQuery(domenove_meno,ns_t_ns);
    runDnsQuery(domenove_meno,ns_t_mx);
    std::string vypis = runDnsQuery(domenove_meno,ns_t_soa);
    //cout << domenove_meno << "\n";
    std::smatch m;
    std::regex soa_email("(SOA)(.+)\\.\\s(.+)(.+)(.+)(.+)\\.");
    if(std::regex_search(vypis,m,soa_email) == true) // ak najde SOA tak to cele sparsuje
    {

      std::string match1 = m[1];
      std::string match2 = m[2];
      std::string match3 = m[3];
      std::string match4 = m[4];
      std::string match5 = m[5];
      std::string match6 = m[6];

      std::stringstream admin_mail,soa;
      soa << match1 << "   " << match2<<".";
      std::string soa_result = soa.str();
      cout << soa_result << "\n";

      std::string replaceDot(".");
      size_t positionDot = match3.find(replaceDot);
      std::string replacnutedot = match3.replace(positionDot,replaceDot.length(),"@");

      admin_mail<<"admin email "  << replacnutedot << match4 << match5 << match6 << "."<< "\n"; // replacnut prvu bodku v match3
      std::string admin_mail_result = admin_mail.str();
      cout << admin_mail_result << "\n";
    }
    else
    {
      printf("SOA RECORDS IS NOT FOUND pls try entry a domain no domain name\n"); // ak nenajde tak vyhodi hlasku
    }




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
    // cout <<"\n\n\nWHOIS IP ADDRESS:\t " << whois << "\n";

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


    cout << "A: " << hostname << "\n";
    std::string whois_domena = getHostname(whois);
    const char* dpc = whois_domena.c_str();

    if(strcmp(dpc,"whois.nic.cz") == 0)
    {
      std::string inputforniccz = getHostname(hostname);

      const char *jebnenma = inputforniccz.c_str();
      if(std::regex_search(inputforniccz,m,std::regex("(www.)")) == true) // ak najde SOA tak to cele sparsuje
      {
        std::string orezane = result;
        std::size_t pos = inputforniccz.find(".");
        std::string nicczbezwww = inputforniccz.substr(pos + 1);
        const char *input_for_nic = nicczbezwww.c_str(); //mobilmania.cz
        strcpy(buf,input_for_nic);
        strcat(buf,"\r\n");
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

        cout << "====== WHOIS:"<< whois_domena <<"  ===========\n";
        //cout << input;
        std::size_t position = input.find("domain:");
        std::string finalinput = input.substr(position);
        cout<<finalinput<<"\n";
      /*  PrintRegexMatch(input,addressReg);
        PrintRegexMatch(input,admin_cReg);
        PrintRegexMatch(input,domianReg);
        PrintRegexMatch(input,registrantReg);
        PrintRegexMatch(input,registrarReg);
        PrintRegexMatch(input,orgReg);
        PrintRegexMatch(input,nameReg);
        PrintRegexMatch(input,contactReg);
        PrintRegexMatch(input,nserverReg);*/
      }
      else
      {

        strcpy(buf,jebnenma);
        strcat(buf,"\r\n");

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

        cout << "====== WHOIS: "<< whois_domena <<"  ===========\n";
      //  cout << input;
        std::size_t position = input.find("domain:");
        std::string finalinput = input.substr(position);
        cout<<finalinput<<"\n";
      /*  PrintRegexMatch(input,addressReg);
        PrintRegexMatch(input,admin_cReg);
        PrintRegexMatch(input,domianReg);
        PrintRegexMatch(input,registrantReg);
        PrintRegexMatch(input,registrarReg);
        PrintRegexMatch(input,orgReg);
        PrintRegexMatch(input,nameReg);
        PrintRegexMatch(input,contactReg);
        PrintRegexMatch(input,nserverReg);*/

      }
    }
    else
    {
      strcpy(buf,hostname);
      strcat(buf,"\r\n");//<CR><LF>
      //  cout << buf;

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

      cout << "====== WHOIS: "<<whois_domena <<"===========\n";
      //cout << input;
      PrintRegexMatch(input,inetnumReg);
      PrintRegexMatch(input,netnameReg);
      /*CIDR in whois.arin.net because i liked it*/
      PrintRegexMatch(input,cidrReg);
      PrintRegexMatch(input,descrReg);
      PrintRegexMatch(input,countryReg);
      PrintRegexMatch(input,admin_cReg);
      PrintRegexMatch(input,addressReg);
      PrintRegexMatch(input,phoneReg);
      PrintRegexMatch(input,rtechPhoneReg);
      PrintRegexMatch(input,orgtechPhoneReg);
      PrintRegexMatch(input,orgAbusePhoneReg);

    }
    close(client_socket);
    printf("\n\n* Closing client socket ...\n");
    //free(daco);
    freeaddrinfo(whois_infoptr);
    freeaddrinfo(client_infoptr);
    freeaddrinfo(dns_infoptr);
    return 0;



}

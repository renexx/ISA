/********************************************************
 * Predmet: ISA FIT VUT 2019                            *
 * Project: WHOIS tazatel - autor zadania Ing. Veselý   *
 * @brief: Hlavný súbor: isa-tazatel.cpp                *
 * @author : René Bolf (xbolfr00@vutbr.cz)              *
 * Komentáre k funkciam sú v - isa-tazatel.h            *
 *******************************************************/
#include "isa-tazatel.h"
using namespace std;    /* or using std::string*/

/*Funkcia, ktorá vypíše help*/
void print_usage()
{
    printf("-q <IP|hostname>, povinny argument\n");
    printf("-w <IP|hostname> WHOIS serveru>, ktorý bude dotazovaný povinný argument\n");
    printf("-d <IP|hostname DNS serveru>, ktorý bude dotazovaný, nepovinny argument pričom implicitne sa bere DNS, ktorý je deafultne v pc\n");
    printf("POUZITE DNS\n");
    printf("Záznam\t\t Mapovanie\n");
    printf("A\t\t doménové meno -> IP adresa\n");
    printf("PTR\t\t IP adresa -> doménové meno\n");
    printf("NS\t\t doména -> doménový server\n");
    printf("MX\t\t doména -> Poštový server\n");
    printf("SOA\t\t doména -> identifikácia správca\n");
    printf("CNAME\t\t doménové meno -> doménové meno\n");
    printf("AAAA\t\t doménové meno -> IPv6 adresa\n");
    exit(2);
}
/*Funkcia na spracovanie regexu */
void PrintRegexMatch(std::string str, std::regex reg)
{
    std::smatch match;
    while(std::regex_search(str,match,reg))
    {
        std::cout << match.str() << "\n";
        str = match.suffix().str();
    }
}
/*Funkcia na preklad IP adresy na doménové meno, prekladá Ipv4 adresu na doménovu adresu*/
std::string getHostname(const char *domName)
{
    struct sockaddr_in klient_adress;
    memset(&klient_adress, 0, sizeof klient_adress);
    klient_adress.sin_family = AF_INET;
    char domain_name[100];
    strcpy(domain_name,domName);

    inet_pton(AF_INET, domain_name, &klient_adress.sin_addr);
    int result = getnameinfo((struct sockaddr*)&klient_adress,sizeof(klient_adress),domain_name,sizeof(domain_name),NULL,0,NI_NAMEREQD);

    std::string ip;
    ip += domain_name;

    return ip;
}
/*Funkcia, ktorá ziťuje IP adresu z doménového mena*/
std::string  hostnameToIp(const char *domName)
{
    struct addrinfo client_adress, *client_infoptr, *client_ptr; /*addrinfo pretože sa používa getaddrinfo je potrebné vytvoriť pointre a následne ich uvolnit pomocou freeaddrinfo(client_infoptr)*/
    int result_for_client; /* uklada sa sem vysledok getaddrinfo či sa to podarilo alebo nie ak to nieje 0 tak sa to nepodarilo*/
    memset(&client_adress,0,sizeof(client_adress));
    memset(&client_infoptr,0,sizeof client_infoptr);
    client_adress.ai_family = AF_UNSPEC;
    client_adress.ai_socktype = SOCK_STREAM;
    client_adress.ai_protocol = 0;
    char hostname[100];
    strcpy(hostname,domName);

    result_for_client = getaddrinfo(hostname,NULL,&client_adress,&client_infoptr); // premena z domeny na IP adresu
    if(result_for_client != 0)
    {
        fprintf(stderr, "%s: %s\n", hostname, gai_strerror(result_for_client));
        exit(EXIT_FAILURE);
    }
    for(client_ptr = client_infoptr; client_ptr != NULL; client_ptr = client_ptr->ai_next)
    {
        getnameinfo(client_ptr->ai_addr,client_ptr->ai_addrlen,hostname,sizeof(hostname),NULL,0,NI_NUMERICHOST); // konvertovanie binarnej adresy do čitatelnej formy
    }
    std::string ip;
    ip += hostname; //premena hostname z charu na string
    freeaddrinfo(client_infoptr); // uvolnenie kvoli getaddrinfo
    return ip;
}

/*Funkcia, ktorá vykonáva DNS dotazy pomocou funkcií z resolv.h*/
std::string runDnsQuery(const char *dname, int nType)
{
    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;
    int x, l;
    int msg_size;
    const u_char *p;

    std::regex a_dns("(A).[1-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?");
    std::regex aaaa_dns("(AAAA)(.+)");
    std::regex mx_dns("MX.+[a-zA-Z]");
    std::regex ns_dns("NS.+\\S");
    std::regex cname_dns("CNAME.*");

    std::cmatch m;
    l = res_search(dname,ns_c_in,nType,nsbuf,N); //c_in internet N je velkost odpovedoveho bufra nsbuf
    if(l < 0)
    {
      return "ERROR";
    }
    if(ns_initparse(nsbuf,l,&msg) < 0)
      return "ERROR";
    for(x = 0; x < ns_msg_count(msg,ns_s_an); x++)
    {
        if(ns_parserr(&msg, ns_s_an, x, &rr) < 0){
          perror("NS PARSERR : "); // ns parrserr extrahuje informacie o zazname odpovedi a ulozi ho do rr čo je parameter odovzdany do inych rutinnych kniznic
          return "ERROR";
        }
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
      /*Parosvanie vystupu DNS zaznamov pomocou regexov*/
        PrintRegexMatch(dispbuf,ns_dns);
        PrintRegexMatch(dispbuf,aaaa_dns);
        PrintRegexMatch(dispbuf,cname_dns);
        PrintRegexMatch(dispbuf,a_dns);
        PrintRegexMatch(dispbuf,mx_dns);
    }
    std::string vypis;
    vypis += dispbuf; // premena char na string pretoze chceme vratit vypis a v maine ho spracovavat kvoli zaznamu SOA, ktorý sa musi samostatne sparsovat
    return vypis;
}
static bool soa_parser(std::string soa_query)
{
  // parsovanie SOA zaznamu, kvoli ziskaniu admin emailu
    std::smatch m;
    std::regex soa_email("(SOA)(.+)\\.\\s(.+)(.+)(.+)(.+)\\."); // Regex na SOA
    if(soa_query == "ERROR")
    {
      cout<<"";
    //  continue;
    }
    if(std::regex_search(soa_query,m,soa_email) == true) // ak najde SOA tak to cele sparsuje
    {

      std::string match1 = m[1]; //SOA
      std::string match2 = m[2]; // druha cela cast napriklad guta.fit.vutbr.cz
      std::string match3 = m[3]; // admin mail teda michal.fit.vutbr.cz
      std::string match4 = m[4]; // .
      std::string match5 = m[5]; // c
      std::string match6 = m[6]; // z
        // spojenie stringov pomocou stringstreamu
      std::stringstream admin_mail,soa;
      soa << match1 << "   " << match2<<"."; // vysledok SOA guta.fit.vutbr.cz.
      std::string soa_result = soa.str();
      cout << soa_result << "\n";

      std::string replaceDot("."); // nahradenie bodky za @
      size_t positionDot = match3.find(replaceDot); //najdeme si poziciu kde sa bodka nachadza
      std::string replacnutedot = match3.replace(positionDot,replaceDot.length(),"@"); // nahradimu ju za zavinac za prvy vyskyt (replaceDot.length())

      admin_mail<<"admin email "  << replacnutedot << match4 << match5 << match6 << "."<< "\n"; // spajanie pomoocu stringstream
      std::string admin_mail_result = admin_mail.str();
      cout << admin_mail_result << "\n"; //vysledok michal@fit.vutbr.cz.
      return true;
    }
    else
      return false;
}
/*Táto funkcia je inspirovana z funkcie z knihy Pána Ing. Petr Matoušek, Ph.D., M.A. kapitola 3. Systém DNS strana 128 funkcia resolve */
std::string  resolvePtr(const char* dname)
{
    in_addr_t addr4;
    register int i;
    int ipAddr[4] = {0,0,0,0};
    char buf[N]; // buffer o velkosti N pričom N má velkost 4096
    std::string nRet;
    if((addr4 = inet_network(dname)) != -1)
    { // funkcia inet_network prevadza retazec v notaci IPv4 čisiel a bodiek na čislo v poradi bajtov (host byte order) ak je vstup neplatný vrati sa -1
      for(i = 0; addr4; )
      {
        ipAddr[i++] = addr4 & 0xFF;
        addr4 >>= 8;
      }
      sprintf(buf,"%u.%u.%u.%u.in-addr.arpa",ipAddr[i % 4], ipAddr[(i+1) % 4], ipAddr[(i+2) % 4], ipAddr[(i+3) % 4]);
      nRet = runDnsQuery(buf,ns_t_ptr); // volanie funkci runDnsQuery kde parameter type je ns_t_ptr
    //  cout <<"PTR " << nRet<<"\n";
      std::smatch m;
      if(std::regex_search(nRet,m,std::regex("(PTR)(\\s*)(.*).")) == true)
      {
        std::string ptr = m[1];
        std::string space = m[2];
        std::string domain_name_in_ptr = m[3];
        std::stringstream ss;
        ss<<ptr<<space<<"\t"<<domain_name_in_ptr;
        std::string print_ptripv4 = ss.str();
        cout<<print_ptripv4<<"\n";
      }
    }
    return nRet;
}
/*FUNKCIA na zaznam PTR pre ipv6 adresu*/
std::string ptripv6(const char* str)
{
    struct in6_addr addr;
    std::string domain_name_in_ptr;
    if(inet_pton(AF_INET6,str,&addr))
    {
      char str2[48];
      char buf[N];
      std::string nRet;
      sprintf(str2,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                            (int)addr.s6_addr[0], (int)addr.s6_addr[1],
                                            (int)addr.s6_addr[2], (int)addr.s6_addr[3],
                                            (int)addr.s6_addr[4], (int)addr.s6_addr[5],
                                            (int)addr.s6_addr[6], (int)addr.s6_addr[7],
                                            (int)addr.s6_addr[8], (int)addr.s6_addr[9],
                                            (int)addr.s6_addr[10], (int)addr.s6_addr[11],
                                            (int)addr.s6_addr[12], (int)addr.s6_addr[13],
                                            (int)addr.s6_addr[14], (int)addr.s6_addr[15]);
     /* Reverovanie ipv6 adresy*/
      std::string reverse = str2;
      int len = reverse.length();
      int n = len - 1;
      for(int i = 0; i < (len/2);i++)
      {
        /* swap */
        char temp = reverse[i];
        reverse[i] = reverse[n];
        reverse[n] = temp;
        n = n - 1;
      }
      /*za každý jeden bit reverzovanej adresy pridáme bodku*/
      std::stringstream ss;
      for(int i = 0; i < reverse.size(); i ++)
      {
        ss << reverse[i] << ".";
      }
      /*IPv6 adresa ktorá je rezervovana a za kazdym bitom je bodka tak k nej pripojime ip6.arpa čo je specialna domena pre uchovavanie ptr záznamov pre ipv6 adresu*/
      std::string vysledok = ss.str();
      vysledok = vysledok + "ip6.arpa";
      const char* ipv6 = vysledok.c_str();
      nRet = runDnsQuery(ipv6,ns_t_ptr); // dotazovanie sa na PTR
      std::smatch m;
      std::string ptr_result;
      /*Parsovanie PTR zaznamu*/
      if(std::regex_search(nRet,m,std::regex("(PTR)(\\s*)(.*).")) == true)
      {
        std::string ptr = m[1];
        std::string medzera = m[2];
        domain_name_in_ptr = m[3];

        std::stringstream join;
        join<< ptr<< medzera<<"\t" << domain_name_in_ptr;
        ptr_result = join.str();
        cout<<ptr_result<<"\n";
        /*Rejyrzvube dotazovanie sa na domenu, ktorá bola zistená z PTR záznamu*/
        std::string aaaa = runDnsQuery(domain_name_in_ptr.c_str(),ns_t_aaaa); //AAAA zaznam
        std::string a = runDnsQuery(domain_name_in_ptr.c_str(),ns_t_a); // A zaznam
        //  cout<<a;
        std::string mx_query = runDnsQuery(domain_name_in_ptr.c_str(),ns_t_mx); //MX zaznam
        std::string ns_query = runDnsQuery(domain_name_in_ptr.c_str(),ns_t_ns); // NS zaznam
        std::string soa_query = runDnsQuery(domain_name_in_ptr.c_str(),ns_t_soa); // SOA zaznam
        std::string cname = runDnsQuery(domain_name_in_ptr.c_str(),ns_t_cname); // CNAME zaznam
        if(soa_parser(soa_query) == false)
        {
          std::size_t pos = domain_name_in_ptr.find(".");
          std:string str3 = domain_name_in_ptr.substr(pos + 1);
          std::string soa_query_authority = runDnsQuery(str3.c_str(),ns_t_soa);
          soa_parser(soa_query_authority);
        }
        else
        cout<<"SOA not found "<<"\n";
      }
    }
    return domain_name_in_ptr;
}
/*Funkcia na pripojenie sa a parsovanie whois serveru whois.nic.cz*/
int whois_nic_cz(std::string input_for_niccz, int client_socket, std::string result)
{
    std::smatch m;
    int bytenasend;
    char buf[BUFFER];
    if(std::regex_search(input_for_niccz,m,std::regex("(www.)")) == true) // tu hladame pomocou regexu ci sa vo vstupe nachadza www. alebo nie ak ano tak musime orezat aby bolo bez wwww
    {
      std::string orezane = result;

      std::size_t pos = input_for_niccz.find("."); // najdeme bodku
      std::string niccz_without_www = input_for_niccz.substr(pos + 1); // a zobereme to co je za bodkov cize o poziciu dalej
      const char *input_for_nic = niccz_without_www.c_str(); //mobilmania.cz
      strcpy(buf,input_for_nic); // do buffru nakopirujeme domenu uz bez www
      strcat(buf,"\r\n"); // whois podla rfc potrebuje \r\n

      bytenasend = send(client_socket, buf, strlen(buf),0); // poslanie poziadavky na server whois.nic.cz
      if (bytenasend == -1)
      {
          perror("ERROR: \n");
      }

      if ((bytenasend = recv(client_socket,buf,BUFFER,MSG_WAITALL)) == -1)
      {  // MSG_WAITALL pri čitani sa čaká na všetky data preto som pouzil recv a nie write
          err(1,"initial read() failed");
      }
      std::string input = buf;

      cout << "====== WHOIS ===========\n";

      if(std::regex_search(input,m,std::regex("(domain:)")) == true)
      {
        std::size_t position = input.find("domain:"); // hladame domain preto od tadial chceme vystup
        std::string finaloutput = input.substr(position);
        cout<<finaloutput<<"\n";

      }
      else
      {
        cout<<"NO entries found "<<"\n";
        return EXIT_FAILURE;
      }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int option;
    int client_socket, port_number, bytenasend, byteread;
    socklen_t len;
    const char *addr;
    struct hostent *hostent_dns;
    extern char *optarg;
    bool q_flag = false;
    bool w_flag = false;
    bool d_flag = false;
    char hostname[100] = "\0", whois[100] = "\0", dns[100] = "\0";
    char buf[BUFFER];
    int i = 0;
    int msg_size;
    struct addrinfo whois_server, *whois_infoptr, *whois_ptr;
    int result_for_whois;
/*Regularne vyrazy pre whois.ripe.net a whois.arin.net*/
  //  string input;
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

/*PARSOVANIE ARGUMENTOV POMOCOU GETOPT()*/
    if(argc < 5 || argc > 7)
    {
        fprintf(stderr, "Error arguments\n");
        print_usage();
    }
    while ((option = getopt(argc, argv, "q:w:d:")) != -1)
    {
       switch (option)
        {
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

/* KED JE zvoleny prepínac -d <IP>*/
    if(d_flag == true)
    {
      char bufferford[16];
      if (inet_pton(AF_INET,dns,bufferford)) // kontrola či je to ip adresa ak nieje skoci sa do else a vypise sa chyba ak je
      {
        res_init(); // inicializujeme res strukturu

        if ((hostent_dns = gethostbyname(dns)) == NULL)
         {
            fprintf(stderr,"ERROR: no such host as %s\n", dns);
            exit(EXIT_FAILURE);
          }
        (void)memcpy((void*)&_res.nsaddr_list[0].sin_addr,(void*)hostent_dns->h_addr_list[0],(size_t)hostent_dns->h_length); // nakopirovanie ip do strukturu res
        _res.nscount = 1; // nastavenie res_nscount na 1 z dôvodu aby sa brala ip ako prvá
      }
      else if(inet_pton(AF_INET6,dns,buf))
      {
        fprintf(stderr, "IPV6 address is not supported %s\n",dns);
        exit(EXIT_FAILURE);
      }
      else
      {
        fprintf(stderr, "NO IP addres as %s\n",dns);
        exit(EXIT_FAILURE);
      }
    }
/*VOLANIE FUNKCII*/
    std::string result = getHostname(hostname); // prevedieme IP adresu na domenove meno pretože funkcie v runDnsQuery pracuju len s domenovym menom
    std::string orezane = result;

    std::size_t pos = orezane.find(".");
    std:string str3 = orezane.substr(pos + 1);

    const char *domenove_meno = result.c_str(); //www.mobilmania.cz
    const char *domain = str3.c_str(); //mobilmania.cz
    std::string ptr_query =resolvePtr(hostname); // volanie funkci na rezoluciu PTR záznamu
    std::string ptripv6a = ptripv6(hostname);
    std::string aaaa = runDnsQuery(domenove_meno,ns_t_aaaa); //AAAA zaznam
    std::string a = runDnsQuery(domenove_meno,ns_t_a); // A zaznam
    std::string mx_query = runDnsQuery(domenove_meno,ns_t_mx); //MX zaznam
    std::string ns_query = runDnsQuery(domenove_meno,ns_t_ns); // NS zaznam
    std::string soa_query = runDnsQuery(domenove_meno,ns_t_soa); // SOA zaznam
    std::string cname = runDnsQuery(domenove_meno,ns_t_cname); // CNAME zaznam
    std::smatch m;
    if(soa_parser(soa_query) == false)
    {
      std::string soa_query_authority = runDnsQuery(domain,ns_t_soa);
      soa_parser(soa_query_authority);
    }
    /*KLIENT WHOIS*/
   /* NASLEDNE prevod domenoveho mena na IP adresu pomocou getaddrinfo a nasledne vytovrenie spojenia pomocou socket */
     memset(&whois_server,0,sizeof(whois_server));  //nastavy dany pocet bytov na hodnotu uvedenu v parametri c cize na 0 a vynulujeme
     memset(&whois_infoptr,0,sizeof whois_infoptr );
     whois_server.ai_family = AF_UNSPEC; // IPV4
     whois_server.ai_socktype = SOCK_STREAM; // TCP
     whois_server.ai_protocol = 0; // implicitna hodnota 0, ktorá spôsobi priradenie vhodného protokolu či už to TCP alebo UDP
     struct in6_addr serveraddr;
     result_for_whois = inet_pton(AF_INET,whois,&serveraddr);
     if(result_for_whois == 1) /*valid ipv4 text address*/
     {
       whois_server.ai_family = AF_INET;
       whois_server.ai_flags |= AI_NUMERICHOST;
     }
     else
     {
       result_for_whois = inet_pton(AF_INET6,whois,&serveraddr);
       if(result_for_whois == 1)
       {
         whois_server.ai_family = AF_INET6;
         whois_server.ai_flags |= AI_NUMERICHOST;
       }
     }

     result_for_whois = getaddrinfo(whois,"43",&whois_server,&whois_infoptr); // preklad domenove mena na IP
     if(result_for_whois != 0)
     {
         fprintf(stderr, "%s: %s\n", whois, gai_strerror(result_for_whois));
         exit(EXIT_FAILURE);
     }

     char old_whois[100];
     strcpy(old_whois,whois);
     for(whois_ptr = whois_infoptr; whois_ptr != NULL; whois_ptr = whois_ptr->ai_next)
     {
         getnameinfo(whois_ptr->ai_addr,whois_ptr->ai_addrlen,whois,sizeof(whois),NULL,0,NI_NUMERICHOST);
         /* Vytvoreni soketu a inicializovanie soketu*/

         if ((client_socket = socket(whois_infoptr->ai_family, whois_infoptr->ai_socktype, whois_infoptr->ai_protocol)) <= 0) /*AF_UNSPEC = IPv4, SOCK_STREAM = TCP, 0 je protokol 0 implicitne vybere podla SOCK_STREAM, inak IPPROTO_TCP*/
         {
             perror("ERROR 224: socket");
             exit(EXIT_FAILURE);
         }

         /*Aktivne otvorenie na strane klienta, druhy parameter funkcie obsahuje ip adresu a port servera*/
         if (connect(client_socket, whois_infoptr->ai_addr, whois_infoptr->ai_addrlen) != 0)
         {
             perror("ERROR 231: connect");
             exit(EXIT_FAILURE);
         }
     }
    std::string ip_hostname = hostnameToIp(hostname); // funkcia ktora prevedie domenove meno na IP
    const char *ip_adress = ip_hostname.c_str();

    if(strcmp(old_whois,"whois.nic.cz") == 0) // porovnava ci sa parameter -w nezhoduje s whois.nic.cz pretoze whois.nic.cz bere domeny preto tu musi byt vyjnimka
    {
      std::string input_for_niccz = getHostname(hostname);
      std::smatch m;
      char bufferis[16];
      if(inet_pton(AF_INET6,hostname,bufferis)) // ak je to ipv6
      {
        std::string input_for_niccz = ptripv6a;
        whois_nic_cz(input_for_niccz,client_socket,result);
      }
      else
      {
        std::string skuskaneviem = getHostname(hostname);
        const char *input_domain_for_niccz = skuskaneviem.c_str();
        whois_nic_cz(input_for_niccz,client_socket,result);
        if(std::regex_search(input_for_niccz,m,std::regex("(www.)")) != true)// ak sa na vstupe nenachadza www
        {
          strcpy(buf,input_domain_for_niccz); // domenu nakopirujeme do buffra
          strcat(buf,"\r\n");
          bytenasend = send(client_socket, buf, strlen(buf),0);
          if (bytenasend == -1)
          {
            perror("ERROR in sendto 270\n");
          }
          if ((bytenasend = recv(client_socket,buf,BUFFER,MSG_WAITALL)) == -1)
          {  // MSG_WAITALL pri čitani sa čaká na všetky data
            err(1,"initial read() failed");
          }
          std::string inputwhoisnic = buf;
          cout << "====== WHOIS  ===========\n";
          //  cout << input;
          std::smatch matchbuf;
          if(std::regex_search(inputwhoisnic,matchbuf,std::regex("(domain:)")) == true)
          {
            std::size_t position = inputwhoisnic.find("domain:"); // hladame domain preto od tadial chceme vystup
            std::string finaloutput = inputwhoisnic.substr(position);
            cout<<finaloutput<<"\n";
          }
          else
          {
            cout<<"NO entries found "<<"\n";
            return EXIT_FAILURE;
          } // ak nenajde domain
        } // ak sa nenachdaza www
      } //ak je to ipv4

    } // al ke to whois.nic

    else // ak to neni whois.nic.cz ale nejaky iny whois server
    {
      strcpy(buf,ip_adress); // ip adresu nakopirujeme do buffra
      strcat(buf,"\r\n");//<CR><LF>

      bytenasend = send(client_socket, buf, strlen(buf),0);
      if (bytenasend == -1)
      {
        perror("ERROR: \n");
      }

      if ((bytenasend = recv(client_socket,buf,BUFFER,MSG_WAITALL)) == -1)
      {  // MSG_WAITALL pri čitani sa čaká na všetky data
        err(1,"initial read() failed");
      }

      std::string input = buf;

      cout << "====== WHOIS:===========\n";
      /* Parsovanie vystupu whois*/
      PrintRegexMatch(input,inetnumReg);
      PrintRegexMatch(input,netnameReg);
      PrintRegexMatch(input,cidrReg);     /*CIDR in whois.arin.net because i liked it*/
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
    freeaddrinfo(whois_infoptr);
    printf("\n\n* Closing client socket ...\n");
    return 0;
}

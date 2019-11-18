# ISA - Síťové aplikace a správa sítí
## Programovanie sieťovej služby - Whois tazatel
### Autor: René Bolf (xbolfr00@stud.fit.vutbr.cz)
# Spúšťanie programu
- -q <IP | hostname> povinný argument
- -w <IP | hostname WHOIS serveru>, ktorý bude dotazovaný, povinný argument
- -d <IP>, ip DNS server, ktorý bude dotazovaná, je to nepovinný argument pričom implicitne sa používa DNS resolver v operačnom systéme
- -h zobrazí help

## Popis riešeného problému
Úlohou bolo naprogramovať klienta pre WHOIS protokol a DNS resolver.
### WHOIS protokol
Je to databáza, ktorá slúži k evidencií údajov o majiteľoch internetových domén a IP adries. Komunikácia je *klient-server* a prebieha pomocou WHOIS protokolu *sieťový port 43*. WHOIS sa používa primárne keď chceme vedieť konkrétne údaje o IP adrese alebo doménovej adrese.
Pri WHOIS ná zaujímaju výstupy : *inetnum, netname, descr, country, address, phone, admin-c*

### DNS resolver
DNS je globálny adresar názvov počítačov a ďalších identifikátorov sieťových zariadení a služieb. Základnou úlohou služby DNS je mapovanie *doménových adries na IP adresy*.
Pri DNS nás zaujímaju tieto DNS záznamy: *A, AAAA, MX, CNAME, NS, SOA, PTR*

## Návrh riešenia a Implementácia
### WHOIS
Program bol riešený pomocou BSD socketov a teda funkcií ako sú
``` cpp socket(int family, int type, int protocol)
```
pre vytvorenie a inicializáciu schránky (socketu).
pre aktívne pripojenie na strane klienta
```cpp int connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
```
 a pre výmenu dát
 ``` cpp ssize_t recv(int sockfd, void *buf, size_t len, int flags)
ssize_t send(int sockfd, const void *msg, size_t len, int flags)
```
Pomocou týchto funkcií je vytvorený klient. Získané údaje z whois servera sú parsované pomocou regulárnych výrazov *reg_search()*
Je potreba sa správne pýtať whois servera, pri *whois.ripe.net* to je IP adresa, pri *whois.nic.cz* to je doména.
Pri výstupe z *whois.ripe.net* sú zobrazené všetky výstupy, ktoré sú uvedené hore v sekci o WHOIS protokole, ale pri *whois.nic.cz* je zobrazená celá správa okrem komentárov, z dôvodu aby ten výstup dával zmysel
### DNS resolver
Pri implementáci DNS resolveru sú využité funkcie  z knižnice *<resolv.h>* a *<arpa/namser.h>*. Tieto knižnice obsahujú funkcie pre zasielanie DNS dotazov a spracovanie odpovedi. Je nutné aby program obsahoval tieto hlavičkové súbory
*#include<sys/types.h>*
*#inlcude<netinet/in.h>*
*#inlcude<resolv.h>*
Funkcia pre zasielanie požiadavok  
```cpp int res search(const char *dname, int class, int type, u char *answer, int len)
 ```
Funkcia na inicializovanie dátovej štruktúry *ns_msg* pre spracovanie odpovedi *init_parse()*
### Prepínač -d a teda dotazovanie sa na iný DNS server ako je imiplicitne v počítači
Je potrebné modifikovať *_res štrukturu*. Na začiatku je potrebné inicializovať celú túto štruktúru a to funkciou *res_init()*. Následne sa IP adresa za -d napriklad -d 8.8.8.8 vloží do *_res.nsaddr_list[0]* a *_res.nscount = 1* týmto sa docieli, že ak bude prepínač -d zadaný tak sa bude dotazovať na zadanú IP adresu DNS servera.

#### Knižnice
```cpp #include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h> // getopt
#include <err.h>
#include <string>
#include <iostream>
#include <regex>
#include <arpa/nameser.h>
#include <resolv.h>
#include <algorithm>
```
#### funkcie
```cpp void print_usage();
void PrintRegexMatch(std::string str, std::regex reg);
std::string getHostname(const char *domName);
std::string hostnameToIp(const char *domName);
std::string runDnsQuery(const char *dname, int nType);
static bool soa_parser(std::string soa_query);
std::string resolvePtr(const char *dname);
std::string ptripv6(const char *str);
int whois_nic_cz(std::string input_for_niccz, int client_socket, std::string result);
```
#### Makrá
```cpp #define BUFFER 65535 // velkost buffra, ktorý je použitý pri send a recv
 #define N 4096 // velkost N ktorá je použitá pri DNS query
```

## Bonus
- Prepínač -d a dotazovanie sa na iný DNS ako je v PC
- PTR záznam a rekurzívne sa dotazovať podla jeho výsledku napr PTR www.fit.vutbr tak sa dotazuje na www.fit.vutbr.cz
## Chýba
- IPv6 DNS pri -d
## zdroje
- Ing. Petr Matoušek, M., Ph.D.: Síťové služby a jejich architektura, VUTIUM,2014. Brno: Nakladatelství
Vysokého učení technického v Brně: VUTIUM, 2014, ISBN 978-80-214-3766-1.
- prednášky z predmetu ISA na FIT VUT
- manualové stránky (resolver, getaddrinfo, atď)
## Odovzdáva sa
- isa-tazatel.cpp
- isa-tazatel.h
- Makefile
- README.md
- dokumentacia.pdf

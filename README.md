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
```cpp makrá
 #define BUFFER 65535 // velkost buffra, ktorý je použitý pri send a recv
 #define N 4096 // velkost N ktorá je použitá pri DNS query
```
## Testovanie
Na svojom osobnom počítači Linux Ubuntu, a na školskom servery merlin.
Pri testovaní som porovnával výsledky pri DNS záznamoch napríklad pomocou:
- https://dnslookup.online/soa.html
- https://dns.google.com/
Pri prepínači -d som testoval rôzne IP adresy a to odtialto
- https://public-dns.info/nameserver/sk.html
a Pri WHOIS stránky ako:
- whois.ripe.net https://apps.db.ripe.net/db-web-ui/#/query
- whois.arin.net
- whois.nic.cz (treba vkladať doménu pozor nato) https://www.nic.cz/whois/
- whois.iana.org(vracia len inetnum alebo nič, pretože referuje na iný whois server) https://www.iana.org/whois

```
./isa-tazatel -q www.fit.vutbr.cz -w whois.ripe.net
======== DNS ===========
AAAA  2001:67c:1220:809::93e5:917
A	147.229.9.23
MX	0 tereza.fit.vutbr.cz
SOA   	guta.fit.vutbr.cz.
admin email michal@fit.vutbr.cz.

====== WHOIS:===========
netname:        VUTBR-TCZ
descr:          VUTBR6-NET
country:        CZ
admin-c:        MS6207-RIPE
address:        Antoninska 548/1
address:        60190
address:        Brno
address:        CZECH REPUBLIC
address:        Brno University of Technology
address:        Antoninska 1
address:        Brno
address:        601 90
address:        The Czech Republic
address:        Brno University of Technology
address:        Center of Computing and Information Services
address:        Antoninska 1
address:        Brno
address:        601 90
address:        The Czech Republic
phone:          +420541145453
phone:          +420 541 145 441
phone:          +420 541145630
```

```
./isa-tazatel -q 147.229.9.23 -w whois.ripe.net
======== DNS ===========
PTR  	www.fit.vutbr.cz
AAAA  2001:67c:1220:809::93e5:917
A	147.229.9.23
MX	0 tereza.fit.vutbr.cz
SOA   	guta.fit.vutbr.cz.
admin email michal@fit.vutbr.cz.

====== WHOIS:===========
inetnum:        147.229.0.0 - 147.229.254.255
netname:        VUTBRNET
descr:          Brno University of Technology
descr:          VUTBR-NET1
country:        CZ
admin-c:        CA6319-RIPE
address:        Brno University of Technology
address:        Antoninska 1
address:        601 90 Brno
address:        The Czech Republic
phone:          +420 541145453
phone:          +420 723047787
```
```
./isa-tazatel -q 2001:67c:1220:809::93e5:917 -w whois.ripe.net
======== DNS ===========
PTR  	www.fit.vutbr.cz
AAAA  2001:67c:1220:809::93e5:917
A	147.229.9.23
MX	0 tereza.fit.vutbr.cz
SOA     guta.fit.vutbr.cz.
admin email michal@fit.vutbr.cz.

====== WHOIS:===========
netname:        VUTBR-TCZ
descr:          VUTBR6-NET
country:        CZ
admin-c:        MS6207-RIPE
address:        Antoninska 548/1
address:        60190
address:        Brno
address:        CZECH REPUBLIC
address:        Brno University of Technology
address:        Antoninska 1
address:        Brno
address:        601 90
address:        The Czech Republic
address:        Brno University of Technology
address:        Center of Computing and Information Services
address:        Antoninska 1
address:        Brno
address:        601 90
address:        The Czech Republic
phone:          +420541145453
phone:          +420 541 145 441
phone:          +420 541145630

```
```
./isa-tazatel -q 2001:67c:1220:809::93e5:917 -w whois.arin.net
======== DNS ===========
PTR  	www.fit.vutbr.cz
AAAA  2001:67c:1220:809::93e5:917
A	147.229.9.23
MX	0 tereza.fit.vutbr.cz
SOA   	guta.fit.vutbr.cz.
admin email michal@fit.vutbr.cz.

====== WHOIS:===========
NetRange:       2001:600:: - 2001:7FF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
NetHandle:      NET6-2001-600-1
NetName:        EU-ZZ-2001-0600
CIDR:           2001:600::/23
Organization:   RIPE Network Coordination Centre (RIPE)
Country:        NL
Address:        P.O. Box 10096
OrgTechPhone:  +31 20 535 4444
OrgAbusePhone:  +31205354444

```
```
./isa-tazatel -q cesnet.cz -w whois.nic.cz
======== DNS ===========
AAAA	2001:718:1:101::4
A	195.113.144.230
MX	100 mail.cesnet.cz
MX	50 cartero.cesnet.cz
MX	10 postino.cesnet.cz
NS	decsys.vsb.cz.
NS	nsa.cesnet.cz.
NS	nsa.ces.net.
SOA   	nsa.cesnet.cz.
admin email hostmaster@cesnet.cz.

====== WHOIS  ===========
domain:       cesnet.cz
registrant:   SB:CESNET-ZSPO
admin-c:      HELMUT_SVERENYAK
admin-c:      J_GRUNTORAD
admin-c:      PV2-RIPE
nsset:        NSS:CESNET-ZSPO:1
keyset:       AUTO-DKBCR1IXC8VDNKW85PFCL8FPB
registrar:    REG-ACTIVE24
registered:   06.10.1996 02:00:00
changed:      06.09.2018 13:10:29
expire:       29.10.2020

contact:      SB:CESNET-ZSPO
org:          CESNET, z.s.p.o.
name:         CESNET, z.s.p.o.
address:      Zikova 4
address:      Praha 6
address:      160 00
address:      CZ
registrar:    REG-ACTIVE24
created:      10.08.2001 22:13:00
changed:      15.05.2018 21:32:00

contact:      HELMUT_SVERENYAK
name:         Helmut Sverenyák
address:      Zikova 4
address:      Praha 6
address:      160 00
address:      CZ
registrar:    REG-ACTIVE24
created:      09.12.2003 09:20:00
changed:      15.05.2018 21:32:00

contact:      J_GRUNTORAD
name:         Jan Gruntorad
address:      Zikova 4
address:      Praha 6
address:      160 00
address:      CZ
registrar:    REG-ACTIVE24
created:      10.08.2001 22:13:00
changed:      15.05.2018 21:32:00

contact:      PV2-RIPE
name:         Pavel Vachek
address:      Zikova 4
address:      Praha 6
address:      160 00
address:      CZ
registrar:    REG-ACTIVE24
created:      10.08.2001 22:13:00
changed:      07.06.2019 16:26:12

nsset:        NSS:CESNET-ZSPO:1
nserver:      decsys.vsb.cz
nserver:      nsa.ces.net
nserver:      nsa.cesnet.cz (195.113.144.228, 2001:718:1:101::144:228)
tech-c:       SB:CESNET-ZSPO
tech-c:       PV2-RIPE
tech-c:       PAVEL_KACHA
tech-c:       AK2268-RIPE
tech-c:       OSKAR
registrar:    REG-ACTIVE24
created:      01.10.2007 02:00:00
changed:      05.12.2017 14:38:50

contact:      PAVEL_KACHA
name:         Pavel Kacha
address:      U Jezírka 873
address:      Unhošť
address:      273 51
address:      CZ
registrar:    REG-IGNUM
created:      10.08.2001 22:13:00
changed:      12.08.2019 14:06:06

contact:      AK2268-RIPE
name:         Andrea Kropacova
address:      CZ
registrar:    REG-CZNIC
created:      10.08.2001 22:13:00
changed:      15.05.2018 21:32:00

contact:      OSKAR
name:         Ondřej Caletka
registrar:    REG-MOJEID
created:      26.10.2010 10:41:13
changed:      26.03.2019 16:06:12

keyset:       AUTO-DKBCR1IXC8VDNKW85PFCL8FPB
dnskey:       257 3 13 Qx/p2aSfnW38FMc/JgnjC+9nwSx3GD8mJVSjgtNDS/ASgnOjjzRa4ecYeZ8UgXZ2XYDftZoeMYCZNUJg4Xbwow==
tech-c:       CZ-NIC
registrar:    REG-CZNIC
created:      06.09.2018 13:10:29
changed:      01.09.2019 14:23:04

contact:      CZ-NIC
org:          CZ.NIC, z.s.p.o.
name:         CZ.NIC, z.s.p.o.
address:      Milesovska 1136/5
address:      Praha 3
address:      130 00
address:      CZ
registrar:    REG-CZNIC
created:      17.10.2008 12:08:21
changed:      15.05.2018 21:32:00
```
```
./isa-tazatel -w 193.0.6.135 -q 147.229.9.23 -d 8.8.8.8
======== DNS ===========
PTR  	www.fit.vutbr.cz
AAAA  2001:67c:1220:809::93e5:917
A	147.229.9.23
MX	0 tereza.fit.vutbr.cz
SOA     guta.fit.vutbr.cz.
admin email michal@fit.vutbr.cz.

====== WHOIS:===========
inetnum:        147.229.0.0 - 147.229.254.255
netname:        VUTBRNET
descr:          Brno University of Technology
descr:          VUTBR-NET1
country:        CZ
admin-c:        CA6319-RIPE
address:        Brno University of Technology
address:        Antoninska 1
address:        601 90 Brno
address:        The Czech Republic
phone:          +420 541145453
phone:          +420 723047787
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

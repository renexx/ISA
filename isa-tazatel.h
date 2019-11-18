/********************************************************
 * Predmet: ISA FIT VUT 2019                            *
 * Project: WHOIS tazatel - autor zadania Ing. Veselý   *
 * @brief: Hlavičkový súbor pre isa-tazatel.cpp         *
 * @author : René Bolf (xbolfr00@vutbr.cz)              *
 *                                                      *
 *******************************************************/

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
#include <err.h>
#include <string>
#include <iostream>
#include <regex>
#include <arpa/nameser.h> // DNS resolver
#include <resolv.h> // DNS resolver

using namespace std;    // Or using std::string;

#define BUFFER 65535 // velkost buffra, ktorý je použitý pri send a recv
#define N 4096 // velkost N ktorá je použitá pri DNS query

/**
 * @brief Funkcia na vypísanie nápovedy
 * @brief funkcia nemá žiadny parameter a ani návratovu hodnotu
 */
void print_usage();

/**
 * @brief Funkcia na prácu s regularnymi výrazmi
 * @param std::string str - je to string, ktorý sa posiela do funkcie reg_search
 * @param std::regex reg - regularny výraz
 * Funkcia je void nemá žiadnu návratovú hodnotu
 */
void PrintRegexMatch(std::string str, std::regex reg);

/**
 * @brief Funkcia na premenu IP na doménové meno
 * @param const char *domName - parameter, ktorý sa posiela do funkcie getnameinfo() pre preklad na doménové meno
 * @return std::string - návratová hodnota je string
 */
std::string getHostname(const char *domName);

/**
 * @brief Funkcia na preklad z doménového mena na IP adresu
 * @param const char *domName - parameter, ktorý sa posiela do funkcie getaddrinfo() pre preklad na IP adresu
 * @return std::string - návratová hodnota je string
 */
std::string hostnameToIp(const char *domName);

/**
 * @brief Funkcia na zaslanie požiadavku na DNS a spracovanie informáci
 * @param const char *domName - doménové meno, na ktoré sa bude dotazovať, posiela sa do funkcie res_search()
 * @param int nType - typ DNS záznamu (ns_t_a, ns_t_aaaa, ns_t_ns, ns_t_ptr, ns_t_mx, ns_t_soa, ns_t_cname)
 * @return std::string - návratová hodnota je string
 */
std::string runDnsQuery(const char *dname, int nType);

/**
 * @brief Funkcia na parsovanie SOA záznamu
 * @param std::string soa_query - string, ktorý je z funkcie runDnsQuery, následne sa používa v ako vstup do regularneho vyrazu
 * @return static bool - bud true alebo false
 */
static bool soa_parser(std::string soa_query);

/**
 * @brief Funkcia na získanie a parsovanie PTR záznamu IPv4 adresy
 * @param const char *dname  vstup na základe, ktorého sa získava PTR
 * @return std::string - funkcia vracia string
 */
std::string resolvePtr(const char *dname);

/**
 * @brief Funkcia na získanie a parsovanie PTR záznamu IPv6 adresy
 * @param const char *str  vstup na základe, ktorého sa získava PTR
 * @return std::string - funkcia vracia string
 */
std::string ptripv6(const char *str);

/**
 * @brief Funkcia na parsovanie whois server whois.nic.cz
 * @param const char *dname  vstup na základe, ktorého sa získava PTR
 * @return int bud exit failure alebo nie
 */
int whois_nic_cz(std::string input_for_niccz, int client_socket, std::string result);

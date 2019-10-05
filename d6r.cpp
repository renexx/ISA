#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt
#include <getopt.h> // for getopt_long
void print_usage()
{
    printf("Usage: d6r -s server [-l] [-d] [-i interface]\n");
    printf("-s DHCP server, na ktorý je poslaný upravený DHCPv6 paket\n");
    printf("-l Zapnutie logovanie pomocou syslog správ\n");
    printf("-d Zapnutie debug výpisu na stadnardný výstup\n");
    printf("-i Rozhranie, na ktorom relay počúva, všetky sietove rozhrania, pokial parameter neni definovany\n");
    exit(2);
}
int main(int argc, char **argv) {
    int option;

    if (argc < 2)
    {
        printf("Zle zadané argumenty\n");
        print_usage();
    }
    while ((option = getopt(argc, argv, "s:ldi:")) != -1){
        switch (option) {
            case 's':
                    printf("serveeeeeer\n");
                    break;
            case 'l':
                    printf("sysloog\n");
                    break;
            case 'd':
                    printf("debug\n");
                    break;
            case 'i':
                    printf("interface\n");
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
    printf("hello\n");
    return 0;
}

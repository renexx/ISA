# Project: Implementácia klienta Whois tazatel
# author René Bolf <xbolfr00@stud.fit.vutbr.cz>
# Debuf prepinač -g (v gdb bude vidno kod)

CC = g++
CFLAGS = -std=c++11
run:
	$(CC) $(CFLAGS) isa-tazatel.cpp -o isa-tazatel -lresolv

clean:
	rm -rf isa-tazatel
	rm -rf isa-tazatel.out

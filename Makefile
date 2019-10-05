CC = g++
CFLAGS = -std=c++11 
run:
	$(CC) $(CFLAGS) d6r.cpp -o d6r 

clean:
	rm -rf d6r
	rm -rf d6r.out

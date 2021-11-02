CXX = g++
CPFLAGS = -Wall -Wextra -pedantic -g
CPLIBS = -lssl -lcrypto -lpcap

all: secret

secret: secret.cpp
	$(CXX) $(CPFLAGS) $(CPLIBS) -o secret secret.cpp

clean:
	rm -rf *.o secret

run: secret
	./secret
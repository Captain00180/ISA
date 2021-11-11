CXX = g++
CPFLAGS = -Wall -Wextra -pedantic -g
CPLIBS = -lssl -lcrypto -lpcap -pthread

all: secret

secret: secret.cpp
	$(CXX) $(CPFLAGS)  -o secret secret.cpp $(CPLIBS)

clean:
	rm -rf *.o secret

run: secret
	./secret

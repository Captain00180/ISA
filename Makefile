CXX = g++
CPFLAGS = -Wall -Wextra -pedantic -g

all: secret

secret: secret.cpp
	$(CXX) $(CPFLAGS) -o secret secret.cpp

clean:
	rm -rf *.o secret

run: secret
	./secret
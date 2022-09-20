COMPILER = g++
FLAGS = -std=c++11

all: scanner

scanner: UdpClient.o UdpPortScanner.o Scanner.o
	$(COMPILER) -o scanner UdpClient.o UdpPortScanner.o Scanner.o $(FLAGS)

Scanner.o: src/main.cpp
	$(COMPILER) -c -o Scanner.o src/main.cpp $(FLAGS)

UdpClient.o: src/UdpClient/UdpClient.cpp
	$(COMPILER) -c src/UdpClient/UdpClient.cpp $(FLAGS)

UdpPortScanner.o: src/UdpPortScanner/UdpPortScanner.cpp
	$(COMPILER) -c src/UdpPortScanner/UdpPortScanner.cpp $(FLAGS)

clear:
	rm -f *.o ./scanner
COMPILER = g++
FLAGS = -std=c++11

all: scanner

scanner: UdpClient.o UdpPortScanner.o Scanner.o
	$(COMPILER) -o scanner UdpClient.o UdpPortScanner.o Scanner.o $(FLAGS)

Scanner.o: src/scanner/main.cpp
	$(COMPILER) -c -o Scanner.o src/scanner/main.cpp $(FLAGS)

UdpClient.o: src/scanner/UdpClient/UdpClient.cpp
	$(COMPILER) -c src/scanner/UdpClient/UdpClient.cpp $(FLAGS)

UdpPortScanner.o: src/scanner/UdpPortScanner/UdpPortScanner.cpp
	$(COMPILER) -c src/scanner/UdpPortScanner/UdpPortScanner.cpp $(FLAGS)

clear:
	rm -f *.o ./scanner ./puzzlesolver
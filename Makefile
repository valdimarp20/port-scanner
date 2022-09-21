COMPILER = g++
FLAGS = -std=c++11

all: scanner puzzlesolver


scanner: UdpClient.o UdpPortScanner.o Scanner.o
	$(COMPILER) -o scanner UdpClient.o UdpPortScanner.o Scanner.o $(FLAGS)

Scanner.o: src/scanner/main.cpp
	$(COMPILER) -c -o Scanner.o src/scanner/main.cpp $(FLAGS)

UdpClient.o: src/scanner/UdpClient/UdpClient.cpp
	$(COMPILER) -c src/scanner/UdpClient/UdpClient.cpp $(FLAGS)

UdpPortScanner.o: src/scanner/UdpPortScanner/UdpPortScanner.cpp
	$(COMPILER) -c src/scanner/UdpPortScanner/UdpPortScanner.cpp $(FLAGS)


puzzlesolver: RawSocketClient.o UdpClient.o UdpPortScanner.o PuzzleSolver.o Solver.o
	$(COMPILER) -o puzzlesolver RawSocketClient.o UdpClient.o UdpPortScanner.o PuzzleSolver.o Solver.o $(FLAGS)

Solver.o: src/solver/main.cpp
	$(COMPILER) -c -o Solver.o src/solver/main.cpp $(FLAGS)

PuzzleSolver.o: src/solver/PuzzleSolver/PuzzleSolver.cpp
	$(COMPILER) -c src/solver/PuzzleSolver/PuzzleSolver.cpp $(FLAGS)

RawSocketClient.o: src/solver/RawSocketClient/RawSocketClient.cpp
	$(COMPILER) -c src/solver/RawSocketClient/RawSocketClient.cpp $(FLAGS)

clear:
	rm -f *.o ./scanner ./puzzlesolver
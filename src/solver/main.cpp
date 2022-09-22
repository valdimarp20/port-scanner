#include <iostream>

#include "PuzzleSolver/PuzzleSolver.h"

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 6) {
        std::cout << "Usage: ./puzzlesolver <ip address>" << std::endl;
        std::cout << "Usage: ./puzzlesolver <ip address> <port1> <port2> <port3> <port4>"
                  << std::endl;
        return 1;
    }
    const char* ipAddress = argv[1];
    int port1 = atoi(argv[2]);
    int port2 = atoi(argv[3]);
    int port3 = atoi(argv[4]);
    int port4 = atoi(argv[5]);

    PuzzleSolver puzzleSolver;
    UdpClient client = UdpClient(ipAddress);
    UdpPortScanner scanner = UdpPortScanner(&client);

    if (port1)

        if (argc == 2) {
            puzzleSolver = PuzzleSolver(ipAddress, &scanner);
        } else {
            puzzleSolver = PuzzleSolver(ipAddress, port1, port2, port3, port4, &scanner);
        }
    puzzleSolver.printPuzzlePorts();

    return 0;
}
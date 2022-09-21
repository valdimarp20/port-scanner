#include <iostream>

#include "PuzzleSolver/PuzzleSolver.h"
#include "RawSocketClient/RawSocketClient.h"

int main(int argc, char* argv[]) {
    // Check if the desired ports are given or not
    if (argc != 2 && argc != 6) {
        std::cout << "Usage: ./puzzlesolver <ip address>" << std::endl;
        std::cout << "Usage: ./puzzlesolver <ip address> <port1> <port2> <port3> <port4>"
                  << std::endl;
        return 1;
        exit(1);
    }
    PuzzleSolver puzzleSolver;
    // dependencies
    UdpClient client = UdpClient(argv[1]);
    UdpPortScanner scanner = UdpPortScanner(&client);
    if (argc == 2) {
        // No ports were supplied via the user
        // Using the PuzzleSolver constructor with one argument, it solves the ports itself

        puzzleSolver = PuzzleSolver(&scanner);
    } else {
        puzzleSolver = PuzzleSolver(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]),
                                    atoi(argv[5]), &scanner);
    }
    puzzleSolver.solvePuzzles();

    return 0;
}
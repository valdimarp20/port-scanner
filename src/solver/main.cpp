#include <iostream>

#include "PuzzleSolver/PuzzleSolver.h"

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 6) {
        std::cout << "Usage: ./puzzlesolver <ip address>" << std::endl;
        std::cout << "Usage: ./puzzlesolver <ip address> <port1> <port2> <port3> <port4>"
                  << std::endl;
        return 1;
    }

    PuzzleSolver puzzleSolver;
    UdpClient client = UdpClient(argv[1]);
    UdpPortScanner scanner = UdpPortScanner(&client);

    if (argc == 2) {
        puzzleSolver = PuzzleSolver(argv[1], &scanner);
    } else {
        puzzleSolver = PuzzleSolver(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]),
                                    atoi(argv[5]), &scanner);
    }
    puzzleSolver.printPuzzlePorts();
    // puzzleSolver.solvePuzzles();

    return 0;
}
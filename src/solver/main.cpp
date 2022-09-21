#include <iostream>

#include "PuzzleSolver/PuzzleSolver.h"
#include "RawSocketClient/RawSocketClient.h"

int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 6) {
        std::cout << "Usage: ./puzzlesolver <ip address>" << std::endl;
        std::cout << "Usage: ./puzzlesolver <ip address> <port1> <port2> <port3> <port4>"
                  << std::endl;
        return 1;
        exit(1);
    }
    PuzzleSolver puzzleSolver;

    if (argc == 2) {
        puzzleSolver = PuzzleSolver(argv[1]);
    } else {
        puzzleSolver =
            PuzzleSolver(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
    }

    RawSocketClient client = RawSocketClient(argv[1]);
    client.createSocket();
    client.setDestinationPort(4026);
    client.createDatagramAndSend("10.2.26.170", "$group_6$");

    return 0;
}
#include "PuzzleSolver.h"

#include <iostream>

PuzzleSolver::PuzzleSolver() {}

PuzzleSolver::PuzzleSolver(const char *ipAddress) {
    this->ipAddress = ipAddress;
}

PuzzleSolver::PuzzleSolver(const char *ipAddress, int port1, int port2, int port3, int port4) {
    this->ipAddress = ipAddress;
    this->port1 = port1;
    this->port2 = port2;
    this->port3 = port3;
    this->port4 = port4;
}

PuzzleSolver::~PuzzleSolver() {}

void PuzzleSolver::printPorts() {
    if (puzzlePortsSet) {
        std::cout << port1 << " " << port2 << " " << port3 << " " << port4 << std::endl;
    } else {
        std::cout << "Puzzle ports not set" << std::endl;
    }
}
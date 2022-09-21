#ifndef PUZZLESOLVER_H
#define PUZZLESOLVER_H

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../scanner/UdpPortScanner/UdpPortScanner.h"

class PuzzleSolver {
    private:
        UdpClient* udpClient;
        UdpPortScanner* udpPortScanner;
        const char *ipAddress;
        void setPortsScan();

    public:
        PuzzleSolver();
        PuzzleSolver(const char *ipAddress);
        PuzzleSolver(const char *ipAddress, int port1, int port2, int port3, int port4);
        virtual ~PuzzleSolver();
        void printPorts();
        void solvePuzzles();
};

#endif  // PUZZLESOLVER_H
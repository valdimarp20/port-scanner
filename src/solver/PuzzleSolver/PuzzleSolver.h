#ifndef PUZZLESOLVER_H
#define PUZZLESOLVER_H

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../scanner/UdpPortScanner/UdpPortScanner.h"

class PuzzleSolver {
    private:
        // UdpClient *udpClient;
        UdpPortScanner *udpPortScanner;
        const char *destIpAddress;
        void setPortsScan();

    public:
        PuzzleSolver();
        PuzzleSolver(UdpPortScanner *udpPortScanner);
        PuzzleSolver(const char *destIpAddress, UdpPortScanner *udpPortScanner);
        PuzzleSolver(const char *destIpAddress, int port1, int port2, int port3, int port4,
                     UdpPortScanner *udpPortScanner);
        virtual ~PuzzleSolver();
        void printPorts();
        void solvePuzzleOne(int port);
        void solvePuzzles();
};

#endif  // PUZZLESOLVER_H
#ifndef PUZZLESOLVER_H
#define PUZZLESOLVER_H

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../scanner/UdpPortScanner/UdpPortScanner.h"

struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
};

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
        void solvePuzzleOne();
        void solvePuzzles();
};

#endif  // PUZZLESOLVER_H
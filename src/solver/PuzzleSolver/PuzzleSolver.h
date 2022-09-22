#ifndef PUZZLESOLVER_H
#define PUZZLESOLVER_H

#include <string>
#include <vector>

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../scanner/UdpPortScanner/UdpPortScanner.h"
#include "../../shared/PortMessagePair.h"

struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
};

class PuzzleSolver {
    private:
        std::string groupMessage = "$group_6$";
        UdpPortScanner *udpPortScanner;
        const char *destIpAddress;
        std::vector<PortMessagePair> portMessagePairs;
        void scanAndSetPorts();

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
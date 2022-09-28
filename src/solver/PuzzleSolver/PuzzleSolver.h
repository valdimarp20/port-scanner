#ifndef PUZZLESOLVER_H
#define PUZZLESOLVER_H

#include <string>
#include <tuple>
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
        const char *destIpAddress;
        std::string groupNumber = "$group_6$";
        UdpPortScanner *udpPortScanner;
        std::vector<PortMessagePair> portMessagePairs;
        std::vector<int> secretPorts;
        std::string secretPhrase;
        int oraclePort;
        void scanAndSetPorts();
        PortMessagePair scanAndGetPortMessagePair(int port);

        std::tuple<std::string, std::string> getChecksumPortChecksumAndSourceIpAddress(
            int checksumPort);
        std::string getChecksumPortSecret(int checksumPort, std::string checksum,
                                          std::string sourceIpAddress);

    public:
        PuzzleSolver();
        PuzzleSolver(UdpPortScanner *udpPortScanner);
        PuzzleSolver(const char *destIpAddress, UdpPortScanner *udpPortScanner);
        PuzzleSolver(const char *destIpAddress, int port1, int port2, int port3, int port4,
                     UdpPortScanner *udpPortScanner);
        virtual ~PuzzleSolver();
        void printPuzzlePorts();
        void printPorts();

        void solveSimplePort(std::string simplePortMessage);
        void solveEvilBitPort(PortMessagePair messagePair);
        void solveChecksumPort(PortMessagePair checksumPuzzle);
        void solveOraclePort();
        void solvePuzzles();
        void test();
};

#endif  // PUZZLESOLVER_H
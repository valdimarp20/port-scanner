#ifndef UDP_PORT_SCANNER_H
#define UDP_PORT_SCANNER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include "../UdpClient/UdpClient.h"

class UdpPortScanner {
    private:
        UdpClient *client;
        std::vector<int> openPorts;

    public:
        UdpPortScanner(UdpClient *client);
        virtual ~UdpPortScanner();
        void displayOpenPorts();
        bool isPortOpen(int port);
        void scanPortRange(int lowPort, int highPort);
};

#endif  // UDP_PORT_SCANNER_H

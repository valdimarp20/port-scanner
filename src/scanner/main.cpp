#include <iostream>

#include "UdpClient/SocketException.h"
#include "UdpClient/UdpClient.h"
#include "UdpPortScanner/UdpPortScanner.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cout << "Usage: /scanner <ip address> <low port> <high port>" << std::endl;
        return 1;
    }
    char *ipAddress = argv[1];
    int lowPort = atoi(argv[2]);
    int highPort = atoi(argv[3]);

    UdpClient client = UdpClient(ipAddress);

    // Set client receive timeout
    try {
        client.setReceiveTimeout(300);
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    UdpPortScanner scanner = UdpPortScanner(&client);
    scanner.scanPortRange(lowPort, highPort);
    scanner.displayOpenPorts();
    return 0;
}

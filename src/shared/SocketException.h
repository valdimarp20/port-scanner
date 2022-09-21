#ifndef SOCKET_EXCEPTION_H
#define SOCKET_EXCEPTION_H

#include <exception>
#include <string>

class SocketException : public std::exception {
    private:
        std::string message = "SocketException: ";

    public:
        SocketException(const std::string &message = "") {
            this->message += message;
        }
        const char *what() {
            return (this->message).c_str();
        }
};

#endif  // SOCKET_EXCEPTION_H
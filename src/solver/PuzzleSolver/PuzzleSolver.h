#ifndef PUZZLESOLVER_H
#define PUZZLESOLVER_H

class PuzzleSolver {
    private:
        const char *ipAddress;
        bool puzzlePortsSet = false;  // True if puzzle ports are set
        int port1;
        int port2;
        int port3;
        int port4;

    public:
        PuzzleSolver();
        PuzzleSolver(const char *ipAddress);
        PuzzleSolver(const char *ipAddress, int port1, int port2, int port3, int port4);
        virtual ~PuzzleSolver();
        void printPorts();
};

#endif  // PUZZLESOLVER_H
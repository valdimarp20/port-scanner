# Scanner Installation
Use `make` or `make scanner` to compile the application.

Use `make clear` to remove compiled code and executable.

# Usage
```sh
./scanner <ip address> <low port> <high port>
```
Scans ports between ```<low port>``` and ```<high port>``` on ```<ip address>```, and displays the open ports found in this range.

`ip address` - Ip address of the machine to scan. \
`low port` - Start port in the scanning range. \
`high port` - End port in the scanning range.


./scanner 130.208.242.120 4000 4100
./puzzlesolver 130.208.242.120
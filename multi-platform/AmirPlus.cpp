#include "LiveFingerprinter.h"
#include <iostream>


int main(int argc, char* argv[]) {
    // Check for correct number of arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << "<IFNAME> <IP_ADDRESS> <PORT>" << std::endl;
        return -1;
    }

    // Parse IP address and port from arguments
    char* ifname = argv[1];
    char* ip = argv[2];
    unsigned short port = static_cast<unsigned short>(std::stoi(argv[3]));
    printf("Getting Signature for %s:%d\n", ip, port);

    LiveFingerprinter lf;
    if (lf.setupPcapAdapter(ifname) < 0){
        printf("Error setting up pcap!\n");
        exit(-1);
    }

    Signature s;
    if (lf.getFingerprint(ip, port, s) < 0){
        printf("Error getting fingerprint\n");
        exit(-1);
    }
}
#include "utils/utils.h"
#include "protocol_analysis.h"
#include "globals.h"
#include <iostream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <fstream>
#include <string>

std::ofstream logFile;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    std::string srcIP = ipToString(&(ipHeader->ip_src));

    int* fileIndex = reinterpret_cast<int*>(userData);
    checkAndRotateLogFile(*fileIndex, logFile);

    analyzeIPHeader(packet);
    detectAnomaly(srcIP);
    analyzeProtocol(ipHeader, packet, pkthdr->len);
    logAggregatedData();
}


int main(int argc, char** argv) {
        
        if (argc > 1) {
        std::string mode(argv[1]);

        if (mode == "report") {
            std::string logFileName = "logs/mainLogFile.txt"; // Ustaw właściwą ścieżkę do pliku log
            std::string reportFileName = generateReport(logFileName);
            std::cout << "Raport został wygenerowany: " << reportFileName << std::endl;
            return 0;
        }
        // Inne tryby działania programu...
    }

    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    int fileIndex = 0;

    descr = pcap_open_live("wlp2s0", BUFSIZ, 0, 1000, errbuf);
    if (descr == NULL) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    logFile.open(getFileName(fileIndex), std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Nie można otworzyć pliku " << getFileName(fileIndex) << " do zapisu." << std::endl;
        return 1;
    }

    if (pcap_loop(descr, -1, packetHandler, reinterpret_cast<u_char*>(&fileIndex)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    logFile.close();
    std::cout << "Capture complete" << std::endl;
    return 0;
}

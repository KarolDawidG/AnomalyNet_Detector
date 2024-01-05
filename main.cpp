#include "utils/utils.h"
#include "protocol_analysis.h"
#include "globals.h"
#include <iostream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <fstream>
#include <string>

ofstream logFile;
string logFileName = "logs/mainLogFile.txt";

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    string srcIP = ipToString(&(ipHeader->ip_src));
    int* fileIndex = reinterpret_cast<int*>(userData);
    checkAndRotateLogFile(*fileIndex, logFile);
    analyzeIPHeader(packet);
    detectAnomaly(srcIP);
    analyzeProtocol(ipHeader, packet, pkthdr->len);
    logAggregatedData();
}


int main(int argc, char** argv) {
    // czy pierwszy argument to "report"
        if (argc > 1) {
        string mode(argv[1]);

        if (mode == "report") {
            string reportFileName = generateReport(logFileName);
            cout << "Raport został wygenerowany: " << reportFileName << endl;
            return 0;
        }
    }

    //sprawdza czy funkcja otrzymala argument 'interface' ze skryptu ./run_monitor
    string interfaceName;
        if (argc > 2 && string(argv[1]) == "--interface") {
            interfaceName = argv[2];
        } else {
            cerr << "Nie podano nazwy interfejsu." << endl;
            return 1;
        }
        //konwersja zmiennej typu string na char*
        const char* cInterfaceName = interfaceName.c_str();
        
 

    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    int fileIndex = 0;

    descr = pcap_open_live(cInterfaceName, BUFSIZ, 0, 1000, errbuf);
    if (descr == NULL) {
        cerr << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    logFile.open(getFileName(fileIndex), ios::out | ios::app);
    if (!logFile.is_open()) {
        cerr << "Nie można otworzyć pliku " << getFileName(fileIndex) << " do zapisu." << endl;
        return 1;
    }

    if (pcap_loop(descr, -1, packetHandler, reinterpret_cast<u_char*>(&fileIndex)) < 0) {
        cerr << "pcap_loop() failed: " << pcap_geterr(descr) << endl;
        return 1;
    }

    logFile.close();
    cout << "Capture complete" << endl;
    return 0;
}

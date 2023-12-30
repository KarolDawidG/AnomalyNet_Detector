#ifndef PROTOCOL_ANALYSIS_H
#define PROTOCOL_ANALYSIS_H

#include <pcap.h>
#include <string>

void analyzeIPHeader(const u_char* packet);
void detectAnomaly(const std::string& srcIP);  // Zmieniono sygnaturę funkcji
void analyzeTCP(const u_char* payload, unsigned int size);
void analyzeUDP(const u_char* payload, unsigned int size);
void analyzeProtocol(const struct ip* ipHeader, const u_char* packet, unsigned int packetSize);

// Deklaracje nowych funkcji pomocniczych
std::string ipToString(const in_addr* addr);

void logAggregatedData();

#endif // PROTOCOL_ANALYSIS_H

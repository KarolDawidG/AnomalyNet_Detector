#ifndef PROTOCOL_ANALYSIS_H
#define PROTOCOL_ANALYSIS_H

#include <pcap.h>

void analyzeIPHeader(const u_char* packet);
void detectAnomaly(const u_char* packet);
void analyzeTCP(const u_char* payload, unsigned int size);
void analyzeUDP(const u_char* payload, unsigned int size);
void analyzeProtocol(const struct ip* ipHeader, const u_char* packet, unsigned int packetSize);

#endif 

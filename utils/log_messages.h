// log_messages.h
#ifndef LOG_MESSAGES_H
#define LOG_MESSAGES_H

#include <string>

using namespace std;

// Definicje stałych stringów dla komunikatów
const string TCP_LOG_MESSAGE = "TCP - Port Src: ";
const string UDP_LOG_MESSAGE = "UDP - Port Src: ";
const string PORT_DST = ", Port Dst: ";
const string ICMP_LOG_MESSAGE = "ICMP - Protocol: ";
const string SCTP_LOG_MESSAGE = "SCTP - Protocol: ";
const string UNKNOWN_PROTOCOL_MESSAGE = "Niezidentyfikowany protokół ID: ";
const string AGGREGATED_STATS = ": Podsumowanie statystyk protokołów (ostatnia minuta):";
const string NETWORK_TRAFFIC_SUMMARY = ": Podsumowanie statystyk ruchu sieciowego (ostatnia minuta):";
const string SUMMARY_HEADER = "====================================================================================";
const string IP_PACKET_COUNT_MESSAGE = " - Liczba pakietów: ";
const string ANOMALY_DETECTED_MESSAGE = ": Wykryto potencjalną anomalię: Ilość: ";
const string ANOMALY_DETECTED_ADRESS = " Adres: "; 

#endif // LOG_MESSAGES_H

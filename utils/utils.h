#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <fstream>
#include <chrono>
#include <map>

using namespace std;

string getCurrentTime();
string getFileName(int index);
long getFileSize(const string& filename);
void checkAndRotateLogFile(int& index, ofstream& logFile);
string generateReport(const string& logFileName);

#endif // UTILS_H

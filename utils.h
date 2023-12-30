#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <fstream>
#include <chrono>
#include <map>

std::string getCurrentTime();
std::string getFileName(int index);
long getFileSize(const std::string& filename);
void checkAndRotateLogFile(int& index, std::ofstream& logFile);

#endif // UTILS_H

#include "utils.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/stat.h>



std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
    return ss.str();
};



std::string getFileName(int index) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm bt = *std::localtime(&in_time_t);

    char dateStr[100];
    strftime(dateStr, sizeof(dateStr), "%d-%m-%Y", &bt);

    std::ostringstream oss;
    oss << "anomalyDetector-" << dateStr;
    if (index > 0) {
        oss << "-" << index;
    }
    oss << ".txt";
    
    return oss.str();
}

long getFileSize(const std::string& filename) {
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

void checkAndRotateLogFile(int& index, std::ofstream& logFile) {
    const long MAX_LOG_SIZE = 1 * 1024 * 1024; // 1 MB  //test
    std::string currentFileName = getFileName(index);
    long fileSize = getFileSize(currentFileName);
    
    if (fileSize >= MAX_LOG_SIZE) {
        logFile.close();
        logFile.open(getFileName(++index), std::ios::out);
    }
}
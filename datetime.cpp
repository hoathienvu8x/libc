#include "datetime.h"
#include <time.h>
#include <cstring>

std::string strtotime(std::string time) {
    time_t rawtime = (time_t) strtol(time.c_str(), NULL, 10);
    char buffer[80];
    struct tm * timeinfo;
    timeinfo = localtime(&rawtime);
    strftime(buffer,sizeof(buffer),"%H:%M:%S",timeinfo);
    return std::string(buffer);
}
std::string strtodate(std::string d) {
    time_t rawtime = (time_t) strtol(d.c_str(), NULL, 10);
    char buffer[80];
    struct tm * timeinfo;
    timeinfo = localtime(&rawtime);
    strftime(buffer,sizeof(buffer),"%F",timeinfo);
    return std::string(buffer);
}
std::string getTimeStamp(time_t epochTime,const char* format) {
    char timestamp[64] = {0};
    strftime(timestamp, sizeof(timestamp), format, localtime(&epochTime));
    return timestamp;
}
std::string getTimeStamp(time_t epochTime) {
    return getTimeStamp(epochTime, "%Y-%m-%d %H:%M:%S");
}
time_t convertTimeToEpoch(const char *theTime,const char *format) {
    std::tm tmTime;
    memset(&tmTime, 0, sizeof(tmTime));
    strptime(theTime, format, &tmTime);
    return mktime(&tmTime);
}
time_t convertTimeToEpoch(const char *theTime) {
    return convertTimeToEpoch(theTime, "%Y-%m-%d %H:%M:%S");
}
bool isTimeString(std::string str) {
    if (str.empty()) {
        return false;
    }
    struct tm tm;
    if (strptime(str.c_str(), "%H:%M:%S", &tm) == NULL) {
        return false;
    }
    return true;
}
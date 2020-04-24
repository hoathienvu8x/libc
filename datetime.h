#ifndef __DATETIME_H
#define __DATETIME_H

#include <string>
#include <ctime>

std::string strtotime(std::string);
std::string strtodate(std::string);
std::string getTimeStamp(time_t,const char*);
std::string getTimeStamp(time_t);
time_t convertTimeToEpoch(const char*,const char*);
time_t convertTimeToEpoch(const char*);
bool isTimeString(std::string);

#endif
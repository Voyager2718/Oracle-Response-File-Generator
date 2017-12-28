If your compiler has good support for C++ (Especially regex), then comment **#define USE_BOOST** to use C++11 official library for regex.

Otherwies, decomment line **#define USE_BOOST** to use boost regex. 

Codes are based on boost 1.59 / gcc 4.8.5 on ORACLE Linux 3.8.13-118.13.3.el7uek (using boost lib) and clang-900.0.39.2 on Mac OS 17.3.0 (using C++11).

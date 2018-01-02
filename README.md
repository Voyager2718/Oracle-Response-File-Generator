If your compiler has good support for C++ (Especially regex), then comment **#define USE_BOOST** to use C++11 official library for regex.

Otherwies, uncomment line **#define USE_BOOST** to use Boost regex. 

Codes are based on Boost 1.59 / gcc 4.8.5 on ORACLE Linux 3.8.13-118.13.3.el7uek (using Boost lib) and clang-900.0.39.2 on Mac OS 17.3.0 (using C++11).

If you are using Boost, then you should use `g++ -I /usr/lib/boost/include -L /usr/lib/boost/lib main.cpp -o rspg -lboost_regex-mt -std=c++11` to compile.

/**
 * If your compiler has good support for C++ (Especially regex), 
 * then comment line "#define USE_BOOST" to use C++11 official library for regex.
 * Otherwies, uncomment line "#define USE_BOOST" to use boost regex. 
 *
 * Codes are based on boost 1.59 / gcc 4.8.5 on ORACLE Linux (3.8.13-118.13.3.el7uek).
 */

#define ALLOW_CORRECTION
#define USE_BOOST
#define VERSION "v0.2.1"

#include <iostream>
#include <string>
#include <sstream> 
#include <fstream>
#include <streambuf>
#include <fstream>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <map>
#include <list>

#ifdef USE_BOOST
#include <boost/regex.hpp>
#else
#include <regex>
#endif

#define DISK_HEAD_IN_BYTES 1024
#define BUFFER_SIZE 1024

using std::cout;
using std::cin;
using std::endl;

using std::string;
using std::getline;
using std::stoi;
using std::to_string;
using std::invalid_argument;

using std::istringstream;
using std::ifstream;
using std::istreambuf_iterator;

#ifdef USE_BOOST
using boost::regex;
using boost::smatch;
using boost::regex_error;
#else
using std::regex;
using std::smatch;
using std::regex_error;
#endif

using std::map;
using std::list;

int numberOfNodes = -1;

int totalError = 0;

bool silentMode = false;

string prefix(string hostname);

string modify(string mayNeedToModify);

/**
  * ==== Convert Functions Part ====
  * Convert functions should be put here.
  * When the parser has extracted the function name, it will invoke callFunction, then callFunction will invoke functions that are written here.
  * Don't forget to add function name and function binding to callFunction. 
  */

string getSCANName(string itemName){
    char hostname[1024];

    gethostname(hostname, sizeof(hostname));

    string hstn(hostname);

    hstn = regex_replace(hstn, regex(string(".us.oracle.com")), string(""));    // Remove suffix.

    string result = prefix(hstn) + "-r";

#ifdef ALLOW_CORRECTION
    if(!silentMode){
        cout<<"SCAN Name detection result: "<<endl;
        result = modify(result);
    }
#endif

    return result;
}

string getClusterNodes(string itemName){
    char hstn[1024];

    gethostname(hstn, sizeof(hstn));

    string hostname(hstn);

    hostname = regex_replace(hostname, regex(string(".us.oracle.com")), string(""));    // Remove suffix.

    string result = "";

    bool isAlphabetic = false;

    string var = "";

    const char *tmpc = hostname.substr(hostname.length() - 2, 1).c_str();
    if(!((int)tmpc[0] >= 48 && (int)tmpc[0] <= 57)){
        isAlphabetic = true;
    }

    var += hostname.substr(hostname.length() - 1, 1);

    for(int i = 1; i < hostname.length(); i++){
        const char *c = hostname.substr(hostname.length() - i - 1, 1).c_str();
        if((isAlphabetic && ((int)c[0] >= 48 && (int)c[0] <= 57)) || (!isAlphabetic && !((int)c[0] >= 48 && (int)c[0] <= 57))){
            break;
        }
        var += hostname.substr(hostname.length() - i - 1, 1);
    }

    var = var.substr(0, 4);

    reverse(var.begin(), var.end());

    int l = var.length();

    string res = "";

    for(int i = 0; i < numberOfNodes; i++){
        try{
            res = to_string((stoi(var) + i));  // string suffix.

            for(int i = res.length(); i < l; i++){
                res = "0" + res;
            }
        }catch(const invalid_argument& e){  // number suffix.
            res = "";
            char c = (char)((int)(var.substr(l - 1, 1).c_str()[0]) + i);
            int carry = (int)((c - 97) / 26);

            if((int) c > 122){
                c = (char)(c - 26);
            }

            res = string(1, c) + res;

            for(int i = 1; i < l; i ++){
                char c = (char)((int)(var.substr(l - i - 1, 1).c_str()[0]) + carry);
                carry = (int)((c - 97) / 26);

                if((int) c > 122){
                    c = (char)(c - 26);
                }

                res = string(1, c) + res;
            }
        }
        string currentHostname = hostname.substr(0, hostname.length() - res.length()) + res;
        result += currentHostname + ":" + currentHostname + "-v:HUB,";
    }

    result = result.substr(0, result.length() - 1);

#ifdef ALLOW_CORRECTION
    if(!silentMode){
    cout<<"Cluster nodes detection result: "<<endl;
    result = modify(result);
    }
#endif

    return result;
} 

string getNetworkInterfaceList(string itemName){
    struct ifaddrs *ifaddr;
    struct sockaddr_in *sa;
    struct sockaddr_in *mask_sa;

    if(getifaddrs(&ifaddr) == -1){
        perror("getifaddrs error.");
        exit(EXIT_FAILURE);
    }

    string result;

    int i = 0;

    do{
        if(ifaddr->ifa_addr->sa_family == AF_INET && string(ifaddr->ifa_name) != "lo" && string(ifaddr->ifa_name).find(":") == std::string::npos){
            sa = (struct sockaddr_in *) ifaddr->ifa_addr;
            mask_sa = (struct sockaddr_in *) ifaddr->ifa_netmask;

            in_addr masked;
            masked.s_addr = (unsigned int) sa->sin_addr.s_addr & (unsigned int)mask_sa->sin_addr.s_addr;
            result += (string(ifaddr->ifa_name) + string(":") + string(inet_ntoa(masked)));

            switch(i){
                case 0: result += ":1,"; break;
                case 1: result += ":5,"; break;
                default:result += ":3,"; break;
            }
            i++;
        }
        ifaddr = ifaddr-> ifa_next;
    }while(ifaddr->ifa_next != NULL);

    result = result.substr(0, result.length() - 1);

#ifdef ALLOW_CORRECTION
    if(!silentMode){
        cout<<"Network interface detection result:"<<endl;
        result = modify(result);
    }
#endif

    return result;
}

string userEdit(string itemName){
    cout<<"Enter the value for <"<<itemName<<">:"<<endl;
    string val;
    cin>>val;
    return val;
}

/**
  * ==== Worker functions ====
  */


// Print detected values and allow user to modify.
string modify(string mayNeedToModify){
    string input;

    while(true){
        cout<<mayNeedToModify<<endl<<"Is this OK? [y/n]"<<endl;
        cin>>input;

        if(input == "y"){
            return mayNeedToModify;
        }else if(input == "n"){
            string result;
            cout<<"Enter a new one:"<<endl;
            cin>>result;
            return result;
        }
    }
}

// Generate SCAN/GNS prefix. (E.g. If node hostname is rws1270317 with 4 nodes, then it will generate rws12703170320)
string prefix(string hostname){
    bool isAlphabetic = false;

    string var = "";

    const char *tmpc = hostname.substr(hostname.length() - 2, 1).c_str();
    if(!((int)tmpc[0] >= 48 && (int)tmpc[0] <= 57)){
        isAlphabetic = true;
    }

    var += hostname.substr(hostname.length() - 1, 1);

    for(int i = 1; i < hostname.length(); i++){
        const char *c = hostname.substr(hostname.length() - i - 1, 1).c_str();
        if((isAlphabetic && ((int)c[0] >= 48 && (int)c[0] <= 57)) || (!isAlphabetic && !((int)c[0] >= 48 && (int)c[0] <= 57))){
            break;
        }
        var += hostname.substr(hostname.length() - i - 1, 1);
    }

    var = var.substr(0, 4);

    reverse(var.begin(), var.end());

    int l = var.length();

    string result = "";

    try{
        result = to_string((stoi(var) + numberOfNodes - 1));  // string suffix.

        for(int i = result.length(); i < l; i++){
            result = "0" + result;
        }
    }catch(const invalid_argument& e){  // number suffix.
        char c = (char)((int)(var.substr(l - 1, 1).c_str()[0]) + numberOfNodes - 1);
        int carry = (int)((c - 97) / 26);

        if((int) c > 122){
            c = (char)(c - 26);
        }

        result = string(1, c) + result;

        for(int i = 1; i < l; i ++){
            char c = (char)((int)(var.substr(l - i - 1, 1).c_str()[0]) + carry);
            carry = (int)((c - 97) / 26);

            if((int) c > 122){
                c = (char)(c - 26);
            }

            result = string(1, c) + result;
        }
    }
    
    return hostname + result;
}    

/* Stringify char* read from disk head.
 * Cannot use string(char*) to do so since char* may not contains printable characters, so that it will cause problem.
 */
string convertToString(char* c, int size){
    string ret = "";
    for(int i = 0 ; i < size ; i++){
        ret += c[i];
    }
    return ret;
}

// Currently this function only detect if there's "ORCL" in the first n kb of input directory.
bool canBeUsedForDG(string diskPath){
    int rd_fd = open(diskPath.c_str(), O_RDONLY);

    if(rd_fd == -1){
        perror(("Unable to open " + diskPath).c_str());
        return false;
    }

    char buffer[BUFFER_SIZE];

    int in_size;

    memset(buffer, 0, BUFFER_SIZE);

    string diskHead = "";

    int i = (DISK_HEAD_IN_BYTES / BUFFER_SIZE) < 1 ? 1 : (DISK_HEAD_IN_BYTES / BUFFER_SIZE);
    while(in_size = read(rd_fd, buffer, BUFFER_SIZE - 1) && i){
        diskHead = convertToString(buffer, sizeof(buffer));
        i--;
    }

    return diskHead.find("ORCL") == string::npos;
}

// Parse template response file and stores them into a map.
map<string,string> parseResponseFileTemplate(string rspPath){
    ifstream rspStream(rspPath);

    string responseFileWithComment((istreambuf_iterator<char>(rspStream)), (istreambuf_iterator<char>()));

    string pureResponseFile = "";

    bool inCommentZone = false;
    
    for(int i = 0; i < responseFileWithComment.length(); i++){
        char currentChar = *(responseFileWithComment.substr(i,1).c_str());
        if(currentChar == '#'){
            inCommentZone = true;
        }else if(currentChar == '\n' && inCommentZone){
            inCommentZone = false;
        }else if(!inCommentZone){
            pureResponseFile += string(1, currentChar);
        }
    }   // Remove comments.

    try{
        pureResponseFile = regex_replace(pureResponseFile, regex(string("\\n\\s*\\n")), string("\n"));

        pureResponseFile = regex_replace(pureResponseFile, regex(string("=\\n")), string("= \n"));  // In order to eliminate duplicated \n.
    }catch(const regex_error& e){
        cout<<e.what()<<" "<<e.code()<<endl;
    }

    pureResponseFile += "\n";   // In order to prevent ignoring the last line.

    map<string, string> m;

    string key, val;

    istringstream iss(pureResponseFile);

    while(getline(getline(iss, key, '='), val)){
        m[key] = val;
    }

    return m;
}

// Call function with their name.
string callFunction(string itemName, string functionName){
    if(functionName == "getSCANName"){
        return getSCANName(itemName);
    }else if(functionName == "getClusterNodes"){
        return getClusterNodes(itemName);
    }else if(functionName == "getNetworkInterfaceList"){
        return getNetworkInterfaceList(itemName);
    }else if(functionName == "userEdit"){
        return userEdit(itemName);
    }

    totalError ++;
    return "-> RSP Generator error: No such function <-";
}

// Parse dynamic values token, and call function to do the conversion.
string parseDynamic(const string fst, const string sec){
    regex rgx(string("\\{\\{[\\s]*(\\w+)[\\s]*\\}\\}"));    // Dynamic call functions in {{ aaa }}.

    smatch match;

#ifdef USE_BOOST
    if(regex_search(sec, match, rgx)){
        return callFunction(fst, match[1]);
    }
#else
    if(regex_search(sec.begin(), sec.end(), match, rgx)){
        return callFunction(fst, match[1]);
    }
#endif

    return "";
}

// Scan the whole map, and call parseDynamic to determine the actual values.
map<string, string> parseFunctions(map<string,string> m){
    string dym;

    for (map<string,string>::iterator it=m.begin(); it!=m.end(); ++it){
        dym = parseDynamic(it->first, it->second);
        if(dym != ""){
            it->second = dym;
        }
    }

    return m;
}

void printUsage(){
    cout<<"Usage: rspg [OPTION]...\n\
Generate response file by local configurations. "<<VERSION<<"\n\n\
  -t <template file>    template file location. Default: template.rsp\n\
  -o <output file>      output location.\n\
  -n <integer>          number of nodes.\n\
  -s                    silent mode. Generated values are not displayed and do not allow users to modify.\n\
  -h                    display the help and exit\n\n\
Template syntax:\n\
  {{<function_name>}}\t<function_name> specifies the function that will be called during the generation.\n\n\
Supported functions:\n\
  getClusterNodes              generate value for oracle.install.crs.config.clusterNodes. E.g. rws1270317:rws1270317-v:HUB\n\
  getNetworkInterfaceList      generate value for oracle.install.crs.config.networkInterfaceList. E.g. eth0:10.214.64.0:1\n\
  getSCANName                  generate value for oracle.install.crs.config.gpnp.scanName. E.g. rws12703170320-r\n\
  userEdit                     let user to determine the value at runtime."<<endl;
}

int main(int argc, char *argv[]){
    int opt, flags;

    string n_nodes, templateLocation = "", outputLocation = "";

    while((opt = getopt(argc, argv, "t:o:n:sh")) != -1){
        switch(opt){
            case 't': templateLocation = string(optarg); break;
            case 'o': outputLocation = string(optarg); break;
            case 'n': 
                n_nodes = string(optarg);
                try{
                    numberOfNodes = stoi(n_nodes);
                }catch(const invalid_argument& e){
                    printUsage(); exit(EXIT_FAILURE);
                }
                break;
            case 's': silentMode = true; break;
            case 'h': printUsage(); exit(EXIT_SUCCESS); break;
            default : printUsage(); exit(EXIT_FAILURE); break;
        }
    }

    if(templateLocation == ""){
        templateLocation = "./template.rsp";
    }

    if(outputLocation == ""){
        cout<<"Enter a location to store response file."<<endl;
        cin>>outputLocation;
    }

    while(numberOfNodes ==
     -1){
        cout<<"Please enter the number of nodes:"<<endl;
        string n_nodes;
        cin>>n_nodes;

        try{
            numberOfNodes = stoi(n_nodes);
            break;
        }catch(const invalid_argument& e){
            continue;
        }
    }

    map<string,string> m = parseFunctions(parseResponseFileTemplate(templateLocation));

    std::fstream fs;
    fs.open(outputLocation, std::fstream::in | std::fstream::out | std::fstream::trunc);

    for (map<string,string>::iterator it=m.begin(); it!=m.end(); ++it){
        if(!silentMode){
            cout<<it->first<<" -> "<<it->second<<endl;
        }
        fs<<it->first<<"="<<it->second<<endl;
    }

    fs.close();

    if(totalError > 0){
        cout<<"\nResponse file Written to "<<outputLocation<<" with "<<totalError<<" error(s)."<<endl;
    }else{
        cout<<"\nResponse file written to "<<outputLocation<<" successfully."<<endl;
    }

    return 0;
}

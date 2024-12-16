#include <iostream>
#include <fstream>    
#include <cstring> 
#include "snort.h"    
using namespace std;

struct TrafficPacket {
    char src_ip[16];
    char src_port[6];
    char dst_ip[16];
    char dst_port[6];
    char protocol[5];
    char data[1024];
};
int main() {
    // Open the input traffic file and the output log file
    ifstream traffic_file("traffic.txt");
    ofstream log_file("result.log");

    if (!traffic_file) {
        cout << "Error opening traffic file." << endl;
        return 1;
    }
    if (!log_file) {
        cout << "Error opening log file." << endl;
        return 1;
    }

    // Read each line from the traffic file and process it
    char traffic_line[1024];
    while (traffic_file.getline(traffic_line, 1024)) {
        TrafficPacket packet;
        if (parseTraffic(traffic_line, packet)) {
            processTraffic(packet, "rules.txt", log_file);
        } else {
            log_file << "Invalid traffic format" << endl;
        }
    }

    // Close the files
    traffic_file.close();
    log_file.close();

    return 0;
}

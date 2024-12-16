#include <iostream>
#include <fstream>
#include <cstring>  // For C-style string functions

using namespace std;

// Structure to represent a traffic packet
struct TrafficPacket {
    char src_ip[16];    // Source IP address
    char src_port[6];   // Source port
    char dst_ip[16];    // Destination IP address
    char dst_port[6];   // Destination port
    char protocol[5];   // Protocol (e.g., TCP, UDP)
    char data[1024];    // Packet data
};

// Structure to represent a rule
struct Rule {
    char action[10];    // Action to be taken (e.g., ALLOW, DENY)
    char protocol[5];   // Protocol (e.g., TCP, UDP)
    char src_ip[16];    // Source IP address
    char src_port[6];   // Source port
    char dst_ip[16];    // Destination IP address
    char dst_port[6];   // Destination port
    char msg[100];      // Message associated with the rule
    int sid;            // Rule ID (SID)
};

// Function to parse each traffic line into meaningful values and store in a TrafficPacket structure
bool parseTraffic(const char* line, TrafficPacket& packet) {
    // Find positions of the relevant fields in the line
    const char* src_pos = strstr(line, "SRC:");
    const char* dst_pos = strstr(line, "DST:");
    const char* pro_pos = strstr(line, "PRO:");
    const char* data_pos = strstr(line, "DATA:");

    // If all fields are found, extract their values
    if (src_pos && dst_pos && pro_pos && data_pos) {
        sscanf(src_pos, "SRC:%[^:]:%[^;];", packet.src_ip, packet.src_port);
        sscanf(dst_pos, "DST:%[^:]:%[^;];", packet.dst_ip, packet.dst_port);
        sscanf(pro_pos, "PRO:%[^;];", packet.protocol);
        sscanf(data_pos, "DATA:%s", packet.data);
        return true;
    }
    return false;
}

// Function to parse a rule line and extract its components into a Rule structure
bool parseRule(const char* line, Rule& rule) {
    // Extract rule components using sscanf
    if (sscanf(line, "%s %s %s %s -> %s %s (msg: \"%[^\"]\"; sid:%d;)", 
        rule.action, rule.protocol, rule.src_ip, rule.src_port, 
        rule.dst_ip, rule.dst_port, rule.msg, &rule.sid) == 8) {
        return true;
    }
    return false;
}

// Function to process the traffic based on the rules and log the output
void processTraffic(const TrafficPacket& packet, const char* rule_file, ofstream& log_file) {
    Rule rule;
    ifstream rule_file_stream(rule_file);
    bool rule_found = false;
    char rule_line[256];

    // Check for matching rule
    while (rule_file_stream.getline(rule_line, 256)) {
        if (parseRule(rule_line, rule)) {
            bool match = true;

            // Check for matching protocol, IPs, and ports
            if (strcmp(rule.protocol, "any") != 0 && strcmp(rule.protocol, packet.protocol) != 0) {
                match = false;
            }
            if (strcmp(rule.src_ip, "any") != 0 && strcmp(rule.src_ip, packet.src_ip) != 0) {
                match = false;
            }
            if (strcmp(rule.src_port, "any") != 0 && strcmp(rule.src_port, packet.src_port) != 0) {
                match = false;
            }
            if (strcmp(rule.dst_ip, "any") != 0 && strcmp(rule.dst_ip, packet.dst_ip) != 0) {
                match = false;
            }
            if (strcmp(rule.dst_port, "any") != 0 && strcmp(rule.dst_port, packet.dst_port) != 0) {
                match = false;
            }

            // If rule matches, log the action
            if (match) {
                log_file << "SRC:" << packet.src_ip << ":" << packet.src_port 
                         << " DST:" << packet.dst_ip << ":" << packet.dst_port 
                         << " PRO:" << packet.protocol << " ACTION:" << rule.action 
                         << " MSG:\"" << rule.msg << "\" SID:" << rule.sid << endl;
                rule_found = true;
                break;
            }
        }
    }

    // If no rule matches, apply PASS action
    if (!rule_found) {
        log_file << "SRC:" << packet.src_ip << ":" << packet.src_port 
                 << " DST:" << packet.dst_ip << ":" << packet.dst_port 
                 << " PRO:" << packet.protocol << " ACTION:PASS "
                 << "MSG:\"Allowed to PASS\" SID:0" << endl;
    }
}

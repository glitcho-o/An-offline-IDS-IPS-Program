#include "snort.h"
int main() {
    // Open the input traffic file and the output log file
    ifstream traffic_file("traffic.txt");
    ofstream log_file("result.log");

    // Check if the traffic file was opened successfully
    if (!traffic_file) {
        cout << "Error opening traffic file." << endl;
        return 1;
    }

    // Check if the log file was opened successfully
    if (!log_file) {
        cout << "Error opening log file." << endl;
        return 1;
    }

    // Buffer to store each line from the traffic file
    char traffic_line[1024];

    // Read each line from the traffic file and process it
    while (traffic_file.getline(traffic_line, 1024)) {
        TrafficPacket packet;

        // Parse the traffic line into a TrafficPacket object
        if (parseTraffic(traffic_line, packet)) {
            // Process the traffic packet using the rules from "rules.txt" and log the result
            processTraffic(packet, "rules.txt", log_file);
        } else {
            // Log an error message if the traffic line format is invalid
            log_file << "Invalid traffic format" << endl;
        }
    }

    // Close the input and output files
    traffic_file.close();
    log_file.close();

    // Inform the user that processing is complete
    cout << "Processing complete. Check result.log for output." << endl;

    return 0;
}


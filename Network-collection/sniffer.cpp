#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <pcap.h>
#include <ctime>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "protocols.h" 

using namespace std;
ofstream outputFile;

// Struct to store configuration settings
struct Config {
    string outputFile;
    int captureDuration;
    string networkInterface;
    bool sourceIP;
    bool destinationIP;
    bool sourcePort;
    bool destinationPort;
    bool protocol;
    bool packageSize;
};

/**
 * @brief Create the output file. If an file with the same name exists, delete it and create a new.
 * 
 * @param filename The name of the file to check.
 * @return true if the file was created, false otherwise.
 * 
 * @note Change file permissions to `0666` (read and write for all users).
 */
bool createOutputFile(const string& filename) {
    struct stat buffer;
    
    // Verify if the file exists
    bool exists = (stat(filename.c_str(), &buffer) == 0);
    
    // If the file exists, remove it.
    if (exists) {
        if (remove(filename.c_str()) != 0) {
            cerr << "Error to remove the file: " << filename << endl;
            return false;
        }
    }

    // Create the file again
    ofstream outfile(filename);
    if (!outfile) {
        cerr << "Error to create the file: " << filename << endl;
        return false;
    }
    
    outfile.close();
    return true;
}

/**
 * @brief THis function reads configuration from config.ini file
 * 
 * @param filename The name of the file to check.
 * @return Config struct object with configuration parameters
 * 
 * @note The code goes through the lines of the configuration file, 
 * separating the key from the value and assigning the configuration variables.
 */
Config readConfig(const string& filename) {
    Config config;
    ifstream file(filename);
    map<string, string> settings;
    string line;

    if (!file) {
        cerr << "Error: Could not open config file.\n";
        exit(1);
    }

    while (getline(file, line)) {
        size_t pos = line.find('=');
        if (pos != string::npos) {
            string key = line.substr(0, pos);
            string value = line.substr(pos + 1);
            settings[key] = value;
        }
    }

    config.outputFile = settings["output_file"];
    config.captureDuration = stoi(settings["capture_duration"]);
    config.networkInterface = settings["network_interface"];
    config.sourceIP = settings["source_ip"] == "true";
    config.destinationIP = settings["destination_ip"] == "true";
    config.sourcePort = settings["source_port"] == "true";
    config.destinationPort = settings["destination_port"] == "true";
    config.protocol = settings["protocol"] == "true";
    config.packageSize = settings["package_size"] == "true";

    return config;
}

/**
 * Callback function to handle captured packets.
 *
 * @param userData Pointer to user data (stores configuration settings).
 * @param pkthdr Pointer to packet header, containing timestamp and length.
 * @param packet Pointer to the raw packet data.
 * 
 * @note Data is collected according to the values ​​assigned in the configuration file.
 * Source and destination port data is collected only for TCP and UDP protocols.
 */
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Converting the userData pointer to a pointer to the Config structure.
    Config* config = reinterpret_cast<Config*>(userData);

    /* Moves the pointer to the beginning of the IP header after the 14 bytes of the Ethernet header, 
    * and converts the pointer to the ip structure. */
    struct ip* ip_header = (struct ip*)(packet + 14);

    // Variables to store packages details
    string srcIP = "", dstIP = "", protocol = "";
    int srcPort = 0, dstPort = 0;

    if (config->sourceIP) {
        srcIP = inet_ntoa(ip_header->ip_src);
    }

    if (config->destinationIP) {
        dstIP = inet_ntoa(ip_header->ip_dst);
    }

    protocol = getProtocolName(ip_header->ip_p);

    if (protocol == "TCP") {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        if (config->sourcePort) {
            srcPort = ntohs(tcp_header->th_sport);
        } 

        if (config->destinationPort){
            dstPort = ntohs(tcp_header->th_dport);
        }
    } else if (protocol == "UDP") {
        struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        if (config->sourcePort) {
            srcPort = ntohs(udp_header->uh_sport);
        } 
                
        if (config->destinationPort) {
            dstPort = ntohs(udp_header->uh_dport);
        }
    }

    // Get timestamp
    time_t now = pkthdr->ts.tv_sec;
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Save to CSV file
    outputFile << timeStr << ",";
    if (config->sourceIP) outputFile << srcIP << ",";
    if (config->destinationIP)outputFile << dstIP << ",";
    if (config->sourcePort) outputFile << srcPort << ",";
    if (config->destinationPort) outputFile << dstPort << ",";
    if (config->protocol) outputFile << protocol << ",";
    if (config->packageSize) outputFile << pkthdr->len << ",";
    outputFile << endl;
}

int main() {
    // Read the configuration file
    Config config = readConfig("config.txt");

    // Verify if the output file exists
    if (createOutputFile(config.outputFile)){
        // Open CSV file
        outputFile.open(config.outputFile);
        if (!outputFile) {
            cerr << "Error: Could not open output file.\n";
            return 1;
        }

        // Write CSV header
        outputFile << "Timestamp,";
        if (config.sourceIP) outputFile << "Source IP,";
        if (config.destinationIP) outputFile << "Destination IP,";
        if (config.sourcePort) outputFile << "Source Port,";
        if (config.destinationPort) outputFile << "Destination Port,";
        if (config.protocol) outputFile << "Protocol,";
        if (config.packageSize) outputFile << "Package Size (bytes),";
        outputFile << endl;

        // Read the network interface in config file and open it for live capture
        char errbuf[PCAP_ERRBUF_SIZE];
        const char* device = config.networkInterface.c_str();
        pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
        
        if (!handle) {
            cerr << "Error opening interface: " << errbuf << endl;
            return 1;
        }

        // Capture packets for the specified duration in config file
        time_t startTime = time(nullptr);
        while (difftime(time(nullptr), startTime) < config.captureDuration) {
            pcap_dispatch(handle, 1, packetHandler, reinterpret_cast<u_char*>(&config));
        }

        // Close the files
        pcap_close(handle);
        outputFile.close();
    }

    return 0;
}

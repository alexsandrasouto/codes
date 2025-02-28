#include <iostream>
#include <netinet/ip.h>   
#include <netinet/if_ether.h>
#include <netinet/tcp.h>   
#include <netinet/udp.h> 
#include <arpa/inet.h>  
#include <pcap.h>
#include <pcap/pcap.h>

using namespace std;


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    /*
     * 
     * 
     */
    
    
    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));

    cout << "----------------------- \n";
    cout << "New  Package! Size: " << pkthdr->len << " bytes\n";
    cout << "Adresses: \n";
    cout << "Source: " << inet_ntoa(ip_header->ip_src) << "\n";
    cout << "Destination: " << inet_ntoa(ip_header->ip_dst) << "\n\n";
    
    if (ip_header->ip_p == IPPROTO_TCP){
         cout << "Protocol: TCP\n" << endl;
         struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
         cout << "Port: \n";
         cout << "Source:" << ntohs(tcp_header->th_sport) << endl;
         cout << "Destination : " << ntohs(tcp_header->th_dport) << " \n\n";
    }
    
    else if (ip_header->ip_p == IPPROTO_UDP){ 
        cout << "Protocol: UDP\n";
        struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
         cout << "Source Port:" << ntohs(udp_header->uh_sport) << endl;
         cout << "Destination Port: " << ntohs(udp_header->uh_dport) << " \n\n";
     }
     
     else{
         cout << "Other protocol: " << (int) ip_header->ip_p << "\n\n";
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error to get interface: " << errbuf << endl;
        return 1;
    }

    pcap_t* handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Error to open  interface\n";
        return 1;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}

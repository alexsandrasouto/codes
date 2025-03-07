#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <unordered_map>
#include <string>
#include <netinet/in.h>

// Mapping IP protocols to string
const std::unordered_map<uint8_t, std::string> PROTOCOL_MAP = {
    {IPPROTO_ICMP, "ICMP"},
    {IPPROTO_TCP, "TCP"},
    {IPPROTO_UDP, "UDP"},
    {IPPROTO_IPV6, "IPv6"},
    {IPPROTO_IGMP, "IFMP"},
    {IPPROTO_ENCAP, "ENCAP"},
    {IPPROTO_ETHERNET, "ETHERNET"},
    {IPPROTO_GRE, "GRE"},
    {IPPROTO_ESP, "ESP"},
    {IPPROTO_AH, "AH"},
    {IPPROTO_SCTP, "SCTP"},
    {IPPROTO_DCCP, "DCCP"},
    {IPPROTO_IP, "IP"},
    {IPPROTO_NONE, "NONE"},
    {IPPROTO_RAW, "RAW"}
};

/**
 * @brief Returns the protocol name corresponding to a numeric value from the IP header.
 * 
 * @param protocol Numeric protocol code (ip_p field from the IP header).
 * @return std::string The corresponding protocol name. If not found, returns "UNKNOWN".
 * 
 * @note The function uses an unordered_map to efficiently look up the protocol name.
 */
inline std::string getProtocolName(uint8_t protocol) {
    auto it = PROTOCOL_MAP.find(protocol);
    return (it != PROTOCOL_MAP.end()) ? it->second : "UNKNOWN";
}

#endif // PROTOCOLS_H


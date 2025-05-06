// traffic.h

#ifndef TRAFFIC_H
#define TRAFFIC_H

#include <pcap.h>
#include <stdbool.h>
#include <stdarg.h>    // for va_list, va_start, va_end
#include "traffic.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>

// Structure to hold configuration for traffic capture
typedef struct {
    const char *interface;     // Network interface (e.g., eth0)
    const char *bpf_filter;    // Optional BPF filter string
    const char *output_file;   // Path to the output PCAP file
    int duration;              // Capture duration in seconds (0 = unlimited)
    int max_packets;           // Max number of packets to capture (0 = unlimited)
    int snaplen;               // Snapshot length (bytes per packet)
    bool promisc;              // Promiscuous mode enabled
} traffic_capture_config_t;

// Start packet capture with the given configuration
int traffic_capture_start(const traffic_capture_config_t *config);

// Stop the current capture gracefully
void traffic_capture_stop(void);

// Get the last error message
const char *traffic_get_last_error(void);

#endif // TRAFFIC_H

#ifndef TRAFFIC_H
#define TRAFFIC_H

#include <pcap/pcap.h>
#include <stdbool.h>

typedef struct {
    const char *interface;
    const char *bpf_filter;
    const char *output_file;
    int duration;
    int max_packets;
    int snaplen;
    bool promisc;
} traffic_capture_config_t;

int traffic_capture_start(const traffic_capture_config_t *config);
void traffic_capture_stop(void);
const char *traffic_get_last_error(void);

#endif  // TRAFFIC_H

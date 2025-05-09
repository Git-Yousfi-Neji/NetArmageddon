
#include "traffic.h"

#include <pcap/pcap.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

enum {
    ERRBUF_SIZE = 256,
    PCAP_TIMEOUT_MS = 1000,
};
static const double MICROSECONDS_IN_SECOND = 1000000.0;

static pcap_t *pcap_handle = NULL;
static pcap_dumper_t *pcap_dumper = NULL;
static volatile int capture_running = 0;
static char errbuf_global[ERRBUF_SIZE];

static void set_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(errbuf_global, ERRBUF_SIZE, fmt, args);  // NOLINT
    va_end(args);
}

void traffic_capture_stop(void) {
    capture_running = 0;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
}

const char *traffic_get_last_error(void) {
    return (errbuf_global[0] != '\0') ? errbuf_global : NULL;
}

int traffic_capture_start(const traffic_capture_config_t *config) {
    struct bpf_program filter_prog;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    char lib_err[PCAP_ERRBUF_SIZE] = {0};
    int packet_count = 0;
    struct timeval start_tv;
    struct timeval now_tv;

    pcap_handle = pcap_open_live(config->interface, config->snaplen, config->promisc ? 1 : 0,
                                 PCAP_TIMEOUT_MS, lib_err);
    if (!pcap_handle) {
        set_error("pcap_open_live failed: %s", lib_err);
        return -1;
    }

    if (config->bpf_filter[0] != '\0') {
        if (pcap_compile(pcap_handle, &filter_prog, config->bpf_filter, 1, net) < 0 ||
            pcap_setfilter(pcap_handle, &filter_prog) < 0) {
            set_error("BPF filter error: %s", pcap_geterr(pcap_handle));
            pcap_freecode(&filter_prog);
            pcap_close(pcap_handle);
            return -1;
        }
        pcap_freecode(&filter_prog);
    }

    pcap_dumper = pcap_dump_open(pcap_handle, config->output_file);
    if (!pcap_dumper) {
        set_error("pcap_dump_open failed: %s", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return -1;
    }

    capture_running = 1;
    gettimeofday(&start_tv, NULL);

    while (capture_running) {
        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int ret = pcap_next_ex(pcap_handle, &hdr, &pkt);

        // Always check elapsed time first
        gettimeofday(&now_tv, NULL);
        double elapsed = (double)(now_tv.tv_sec - start_tv.tv_sec) +
                         (double)(now_tv.tv_usec - start_tv.tv_usec) / MICROSECONDS_IN_SECOND;

        if (config->duration > 0 && elapsed >= config->duration) {
            break;
        }

        if (ret == 1) {
            pcap_dump((u_char *)pcap_dumper, hdr, pkt);
            packet_count++;
            if (config->max_packets > 0 && packet_count >= config->max_packets) {
                break;
            }
        } else if (ret < 0) {
            set_error("pcap_next_ex error: %s", pcap_geterr(pcap_handle));
            break;
        }
    }

    pcap_dump_close(pcap_dumper);
    pcap_close(pcap_handle);
    capture_running = 0;
    return 0;
}

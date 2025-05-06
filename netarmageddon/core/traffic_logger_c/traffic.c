// traffic.c

#include "traffic.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>

// Global handles and state
static pcap_t                  *pcap_handle     = NULL;
static pcap_dumper_t           *pcap_dumper     = NULL;
static volatile sig_atomic_t    capture_running = 0;
static char                     errbuf_global[256] = {0};

// Internal helper to set last error
static void set_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf_global, sizeof(errbuf_global), fmt, ap);
    va_end(ap);
}

// Signal‐safe stop handler (if you want to hook SIGINT)
//static void handle_sigint(int signo)
//{
//    (void)signo;
//    capture_running = 0;
//}

// Start packet capture with the given configuration
int traffic_capture_start(const traffic_capture_config_t *config)
{
    struct bpf_program fp;
    bpf_u_int32      net, mask;
    struct timeval   start_tv, now_tv;
    int              packet_count = 0;

    if (capture_running) {
        set_error("Capture already running");
        return -1;
    }

    // Prepare error buffer for libpcap calls
    char lib_err[PCAP_ERRBUF_SIZE] = {0};

    // 1. Lookup network & mask (we don't strictly need them for live capture)
    if (pcap_lookupnet(config->interface, &net, &mask, lib_err) < 0) {
        // Not fatal: we can still capture without knowing net/mask
        net = mask = 0;
    }

    // 2. Open live capture
    pcap_handle = pcap_open_live(
        config->interface,
        config->snaplen,
        config->promisc ? 1 : 0,
        1000,         // read timeout in ms
        lib_err
    );
    if (!pcap_handle) {
        set_error("pcap_open_live failed: %s", lib_err);
        return -1;
    }

    // 3. Compile & set filter if provided
    if (config->bpf_filter && *config->bpf_filter) {
        if (pcap_compile(pcap_handle, &fp, config->bpf_filter, 1, net) < 0) {
            set_error("pcap_compile failed: %s", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            pcap_handle = NULL;
            return -1;
        }
        if (pcap_setfilter(pcap_handle, &fp) < 0) {
            set_error("pcap_setfilter failed: %s", pcap_geterr(pcap_handle));
            pcap_freecode(&fp);
            pcap_close(pcap_handle);
            pcap_handle = NULL;
            return -1;
        }
        pcap_freecode(&fp);
    }

    // 4. Open dumper
    pcap_dumper = pcap_dump_open(pcap_handle, config->output_file);
    if (!pcap_dumper) {
        set_error("pcap_dump_open failed: %s", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        return -1;
    }

    // 5. Install SIGINT handler so ctrl-C in C layer works (optional)
    //signal(SIGINT, handle_sigint);

    // 6. Initialize run loop
    capture_running = 1;
    gettimeofday(&start_tv, NULL);

    while (capture_running) {
        struct pcap_pkthdr *header;
        const u_char       *packet;
        int                 ret;

        // Check duration limit
        if (config->duration > 0) {
            gettimeofday(&now_tv, NULL);
            long elapsed = now_tv.tv_sec - start_tv.tv_sec;
            if (elapsed >= config->duration) {
                break;
            }
        }

        // Fetch next packet (timeout returns 0)
        ret = pcap_next_ex(pcap_handle, &header, &packet);
        if (ret == 1) {
            // Dump it
            pcap_dump((u_char*)pcap_dumper, header, packet);
            packet_count++;

            // Check packet count limit
            if (config->max_packets > 0 && packet_count >= config->max_packets) {
                break;
            }
        }
        else if (ret == -1) {
            // Fatal error
            set_error("pcap_next_ex error: %s", pcap_geterr(pcap_handle));
            break;
        }
        // ret == 0 means timeout, just loop again
        // ret == -2 means EOF on savefile, but here we do live capture so unlikely
    }

    // Cleanup
    pcap_dump_close(pcap_dumper);
    pcap_close(pcap_handle);
    pcap_dumper  = NULL;
    pcap_handle  = NULL;
    capture_running = 0;

    return 0;
}

// Stop the current capture gracefully
void traffic_capture_stop(void)
{
    capture_running = 0;
}

// Get the last error message
const char *traffic_get_last_error(void)
{
    if (errbuf_global[0] == '\0') {
        return NULL;
    }
    return errbuf_global;
}

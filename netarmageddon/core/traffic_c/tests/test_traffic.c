#include <check.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../traffic.h"

static void* capture_thread_wrapper(void* arg) {
    traffic_capture_config_t* cfg = (traffic_capture_config_t*)arg;
    int* result = malloc(sizeof(int));
    *result = traffic_capture_start(cfg);
    return result;
}

START_TEST(test_valid_capture_config) {
    traffic_capture_config_t cfg = {.interface = "lo",
                                    .bpf_filter = "icmp",
                                    .output_file = "test.pcap",
                                    .duration = 2,
                                    .max_packets = 1,
                                    .snaplen = 65535,
                                    .promisc = 1};

    pthread_t capture_thread;
    int* result_ptr = NULL;

    pthread_create(&capture_thread, NULL, capture_thread_wrapper, &cfg);

    usleep(200000);  // 200ms delay

    int __attribute__((unused)) ping_ret = system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
    pthread_join(capture_thread, (void**)&result_ptr);

    int result = *result_ptr;
    free(result_ptr);

    ck_assert_msg(result == 0, "Capture failed with error: %s", traffic_get_last_error());
    traffic_capture_stop();
}
END_TEST

START_TEST(test_invalid_interface) {
    traffic_capture_config_t cfg = {.interface = "invalid_interface",
                                    .bpf_filter = "",
                                    .output_file = "test.pcap",
                                    .duration = 1,
                                    .max_packets = 1,
                                    .snaplen = 65535,
                                    .promisc = 0};

    int result = traffic_capture_start(&cfg);
    ck_assert_int_eq(result, -1);
    const char* err = traffic_get_last_error();
    ck_assert_ptr_nonnull(err);
    printf("Expected error: %s\n", err);
}
END_TEST

Suite* traffic_suite(void) {
    Suite* s;
    TCase* tc_core;

    s = suite_create("Traffic");
    tc_core = tcase_create("Core Tests");

    tcase_add_test(tc_core, test_valid_capture_config);
    tcase_add_test(tc_core, test_invalid_interface);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite* s;
    SRunner* sr;

    s = traffic_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

CC = gcc
CFLAGS = -fPIC -O2 -pthread $(shell pkg-config --cflags libpcap check) -DCHECK_TIMEOUT=30
LDFLAGS = $(shell pkg-config --libs libpcap) -pthread
CHECK_FLAGS = $(shell pkg-config --libs check)

OBJ = traffic.o
TARGET = libtraffic.so

TEST_SRC = tests/test_traffic.c
TEST_EXE = tests/test_traffic
TEST_PCAP_FILE = tests/test.pcap

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.c traffic.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_EXE): $(TEST_SRC) $(TARGET)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(TARGET) $(CHECK_FLAGS) $(LDFLAGS)

test: $(TEST_EXE)
	LD_LIBRARY_PATH=. $(TEST_EXE)

clean:
	rm -rf $(OBJ) $(TARGET) $(TEST_EXE) $(TEST_PCAP_FILE)

CC        := gcc
CFLAGS    := -fPIC -O2 -pthread $(shell pkg-config --cflags libpcap check) -DCHECK_TIMEOUT=30
LDFLAGS   := $(shell pkg-config --libs libpcap) -pthread
CHECK_FLAGS := $(shell pkg-config --libs check)

# sources and headers
OBJ       := traffic.o
TARGET    := libtraffic.so

# tests
TEST_DIR             := tests
TEST_SRC             := $(wildcard $(TEST_DIR)/*.c)
TEST_EXE             := $(TEST_DIR)/test_traffic
TEST_PCAP            := $(TEST_DIR)/test.pcap
COMPILE_COMMANDS     := compile_commands.json

all: $(TARGET) $(TEST_EXE)

$(TARGET): $(OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.c traffic.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_EXE): $(TEST_SRC) $(TARGET)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(TARGET) $(CHECK_FLAGS) $(LDFLAGS)

test: $(TEST_EXE)
	LD_LIBRARY_PATH=. $(TEST_EXE)

format:
	@clang-format -i traffic.c traffic.h $(TEST_SRC)

lint:
	@clang-tidy traffic.c traffic.h \
	  -p . \
	  --header-filter='.*' \
	  --quiet

clean:
	-rm -f $(OBJ) $(TARGET) $(TEST_EXE) $(TEST_PCAP) compile_commands.json

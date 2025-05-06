CC	  = gcc
CFLAGS += -fPIC -O2 $(shell pkg-config --cflags libpcap)
LDFLAGS += $(shell pkg-config --libs libpcap)
SRC	 = traffic.c
OBJ	 = traffic.o
TARGET  = libtraffic.so

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.c traffic.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

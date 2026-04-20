TARGET = traceroute

CC = gcc
CFLAGS = -std=gnu18 -Wall -Wextra

all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CC) $(CFLAGS) $(TARGET).o -o $(TARGET)

$(TARGET).o: $(TARGET).c
	$(CC) $(CFLAGS) -c $(TARGET).c -o $(TARGET).o

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGET)

.PHONY: all clean distclean

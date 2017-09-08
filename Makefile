CFLAGS += -g -Wall -Wunused
CFLAGS += -Wextra -Wcast-qual -Werror
LDLIBS = -lpthread

TARGETS = test_checksum

all: $(TARGETS)

clean:
	rm -f $(TARGETS) *~ *.o *.out

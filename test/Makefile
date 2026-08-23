# Host side check for the NDEF encoders, which produce the bytes that end up
# written to a tag and so are worth pinning down without hardware.
#
#   make -C test && ./test/test-ndef
#
# Only glib is needed: the JSON side of ndef.c is stubbed out here.

CFLAGS += -Wall -Wextra -Wno-unused-parameter -I ../src -I stubs $(shell pkg-config --cflags glib-2.0)
LDLIBS += $(shell pkg-config --libs glib-2.0)

test-ndef: test-ndef.c ../src/ndef.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

.PHONY: check clean
check: test-ndef
	./test-ndef

clean:
	rm -f test-ndef

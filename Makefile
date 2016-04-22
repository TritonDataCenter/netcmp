#
# Makefile for netcmp tool
#

CPPFLAGS = -g -std=c99 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
CFLAGS   = -Wall -Werror -Wextra
LDFLAGS  = -lavl

netcmp: netcmp.c
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^

clean:
	rm -f netcmp

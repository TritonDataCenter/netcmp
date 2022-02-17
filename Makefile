#
# Makefile for netcmp tool
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright 2022 Joyent, Inc.

CPPFLAGS = -g -std=c99 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
CFLAGS   = -Wall -Werror -Wextra
LDFLAGS  = -lavl

netcmp: netcmp.c
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^

clean:
	rm -f netcmp

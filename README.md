<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at https://mozilla.org/MPL/2.0/. -->

<!--
  -- Copyright 2022 Joyent, Inc.
  -->

# netcmp: compare netstat output from multiple systems

This is a work-in-progress tool for comparing the output of:

    netstat -f inet -P tcp -n

from multiple systems.  This can be used to identify cases where a TCP
connection has been abandoned on one side but not the other.

This is still pretty incomplete.  See the TODO in netcmp.c for details.

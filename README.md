# netcmp: compare netstat output from multiple systems

This is a work-in-progress tool for comparing the output of:

    netstat -f inet -P tcp -n

from multiple systems.  This can be used to identify cases where a TCP
connection has been abandoned on one side but not the other.

This is still pretty incomplete.  See the TODO in netcmp.c for details.

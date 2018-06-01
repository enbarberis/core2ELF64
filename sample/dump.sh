#!/bin/sh
echo 0x07 > /proc/$1/coredump_filter
gcore $1

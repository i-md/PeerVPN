#! /bin/bash

cc -g -c -o peervpn.o peervpn.c
cc -g peervpn.o -lssl -lcrypto -ldl -lz -o peervpn

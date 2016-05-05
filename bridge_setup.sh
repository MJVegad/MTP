#!/bin/bash
sudo brctl addbr kvmbr0
sudo brctl addif kvmbr0 em1
sudo ifconfig em1 0
sudo ifconfig kvmbr0 10.129.26.28 netmask 255.255.0.0
sudo route add default gw 10.129.250.1 kvmbr0

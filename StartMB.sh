#!/bin/bash

rm /dev/shm/$1
qemu-system-x86_64 $2 -m 2048 -enable-kvm -device ivshmem,shm=$1,size=1

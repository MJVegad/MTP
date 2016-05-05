#!/bin/bash
virt-install --name=sandbox --ram=1024 --vcpus=1 --os-type=linux \
  --autostart --disk=path=./vm/disks/sandbox.img,size=50 \
  --graphics=vnc,listen=0.0.0.0,port=5900 --noautoconsole \
  --cdrom=./ubuntu-14.04.4-desktop-amd64.iso

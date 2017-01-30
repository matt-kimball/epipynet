#!/bin/sh

BINS="\
    bin/epipynet-apply-config \
    bin/epipynet-autoconfigure \
    bin/epipylon-resize-fs"
PYTHON_LIB=$(python3 -c 'import sys; print(sys.path[-1])')

mkdir -p /usr/share/epipynet
cp share/search-networks /usr/share/epipynet

cp $BINS /usr/sbin

cp -r etc/systemd /etc
cp -r lib/epipynet $PYTHON_LIB

systemctl enable epipynet.service
systemctl enable epipylon-resize-fs.service

#!/bin/sh

TIMESTAMP=$(date +%Y%m%d%H%M%S)
VERSION=0.1
PACKAGE=epipynet_$VERSION-$TIMESTAMP

BINS="\
    bin/epipynet-apply-config \
    bin/epipynet-autoconfigure"

LIBS="\
    lib/epipynet/__init__.py \
    lib/epipynet/arp.py \
    lib/epipynet/detect.py \
    lib/epipynet/dhcp.py"

SYSTEMD="\
    systemd/epipynet.service"

DEBIAN="\
    debian/postinst \
    debian/prerm"

rm -fr $PACKAGE
mkdir -p $PACKAGE/DEBIAN

cat <<CONTROL_END >$PACKAGE/DEBIAN/control
Package: epipynet
Version: $VERSION-$TIMESTAMP
Architecture: all
Section: net
Priority: optional
Depends: python3, python3-typing, iproute2, systemd, dnsmasq
Maintainer: Matt Kimball <matt.kimball@gmail.com>
Homepage: http://www.epipylon.com/
Description: Epipylon Network Configuration Daemon
 A daemon which will autoconfigure the network by using DHCP,
 or by discovering a router with ARP probes.
CONTROL_END

chmod a+rx $DEBIAN
cp $DEBIAN $PACKAGE/DEBIAN

mkdir -p $PACKAGE/usr/sbin
cp $BINS $PACKAGE/usr/sbin

mkdir -p $PACKAGE/usr/lib/python3/dist-packages/epipynet
cp $LIBS $PACKAGE/usr/lib/python3/dist-packages/epipynet

mkdir -p $PACKAGE/usr/share/epipynet
cp share/search-networks $PACKAGE/usr/share/epipynet

mkdir -p $PACKAGE/lib/systemd/system
cp $SYSTEMD $PACKAGE/lib/systemd/system

chown -R root.root $PACKAGE
dpkg-deb --build $PACKAGE

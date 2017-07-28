#!/bin/sh
#
#    epipynet - Epipylon network configuration
#    Copyright (C) 2017  Matt Kimball
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

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
    lib/epipynet/dhcp.py \
    lib/epipynet/netconfig.py"

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

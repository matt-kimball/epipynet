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

PY_BINS="\
    bin/epipynet-autoconfigure \
    bin/epipynet-apply-config"

PY_SOURCE="$(find lib -name '*.py')"

pep8 $PY_SOURCE

for bin in $PY_BINS
do
    pep8 $bin
    MYPYPATH=lib mypy $bin $PY_SOURCE
done

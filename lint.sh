#!/bin/sh

PY_BINS="\
    bin/epipynet-autoconfigure \
    bin/epipynet-apply-config"

PY_SOURCE="$(find . -name '*.py')"

pep8 $PY_SOURCE

for bin in $PY_BINS
do
    pep8 $bin
    MYPYPATH=lib mypy $bin $PY_SOURCE
done

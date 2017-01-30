#!/bin/sh

TESTS="\
    test/netdetect.py"

PYTHONPATH=lib python3 $TESTS

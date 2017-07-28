# Overview

epipynet is part of Epipylon -- http://www.epipylon.com/

epipynet's purpose is to automatically detect the network environment
and configure the Epipylon system.

First, epipynet will look for an existing DHCP server on the network,
and store persistent configuration based on the information reported
by it.  If that fails, epipynet will send ARP requests to common private
network IP addresses in an attempt to the subnet range and router address
of the attached network.

After discovering the network environment, epipynet will write a persistent
configuration for use on subsequent boots and generate system files 
necessary for operation, including a configuration for DNSmasq.

# Contents

epipynet contains the following components:

* `bin/epipynet-apply-config` - Apply stored configuration
* `bin/epipynet-autoconfigure` - Daemon for probing network configuration
* `debian/` - Scripts related to package installation
* `lib/epipynet/` - Python libraries used by the tools in `bin/`
* `share/search-networks` - List of common networks and router IPs
* `systemd/epipynet.service` - Systemd config to start autoconfigure at boot
* `test/` - Automated tests for epipynet

# Development

The first step in development is installing the Epipylon development
image on your Raspberry Pi.

See http://www.epipylon.com/index.html#development for the development
image.

After installation, log in to your Raspberry Pi and clone the epibase
repository.

    ssh epipylon@epipylon.local  # password is 'epipylon'
    git clone https://github.com/matt-kimball/epipynet.git
    cd epipynet

You'll need a few more tools for development:

    sudo pip3 install mypy pep8

After making changes, use mypy to check for correctness and run the
automated tests:

    ./lint.sh
    sudo ./test.sh

If everything looks good, you can generate a new package and install it
locally:

    sudo ./package.sh
    sudo dpkg -i epipynet_0.1-XXXX.deb  # where XXXX is the package timestamp

The `clean.sh` script can be used to remove all built packages.

Before submitting pull requests, please ensure that changed Python code has
mypy type annotations.

# License

epipynet is licensed under the GNU General Public License 2.0.

#!/bin/sh

# Many of neutron's repos suffer from the problem of depending on neutron,
# but it not existing on pypi.

# This wrapper for tox's package installer will use the existing package
# if it exists, else use zuul-cloner if that program exists, else grab it
# from neutron master via a hard-coded URL. That last case should only
# happen with devs running unit tests locally.

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

set -e

echo "PIP HARDCODE" > /tmp/tox_install.txt
pip install -U -egit+https://git.openstack.org/openstack/neutron@stable/liberty#egg=neutron

pip install -U $*
exit $?

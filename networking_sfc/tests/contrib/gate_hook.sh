#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}
export DEVSTACK_LOCAL_CONFIG="enable_plugin networking-sfc https://git.openstack.org/openstack/networking-sfc"

case $VENV in
    dsvm-functional )
        ;;
    api) $BASE/new/devstack-gate/devstack-vm-gate.sh ;;
esac

#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
NETWORKING_SFC_PATH=$GATE_DEST/networking-sfc
GATE_HOOKS=$NETWORKING_SFC_PATH/networking_sfc/tests/contrib/hooks
DEVSTACK_PATH=$GATE_DEST/devstack
LOCAL_CONF=$DEVSTACK_PATH/late-local.conf
DSCONF=/tmp/devstack-tools/bin/dsconf

# Install devstack-tools used to produce local.conf; we can't rely on
# test-requirements.txt because the gate hook is triggered before neutron is
# installed
sudo -H pip install virtualenv
virtualenv /tmp/devstack-tools
/tmp/devstack-tools/bin/pip install -U devstack-tools==0.4.0

# Inject config from hook into localrc
function load_rc_hook {
    local hook="$1"
    local tmpfile
    local config
    tmpfile=$(tempfile)
    config=$(cat $GATE_HOOKS/$hook)
    echo "[[local|localrc]]" > $tmpfile
    $DSCONF setlc_raw $tmpfile "$config"
    $DSCONF merge_lc $LOCAL_CONF $tmpfile
    rm -f $tmpfile
}


# Inject config from hook into local.conf
function load_conf_hook {
    local hook="$1"
    $DSCONF merge_lc $LOCAL_CONF $GATE_HOOKS/$hook
}


case $VENV in
"dsvm-functional"|"dsvm-fullstack")
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=networking-sfc
    IS_GATE=True
    LOCAL_CONF=$DEVSTACK_PATH/local.conf

    source $DEVSTACK_PATH/functions

    source $NEUTRON_PATH/devstack/lib/ovs
    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing

    load_conf_hook ovs
    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE
    ;;
"dsvm-networking-sfc")
    load_rc_hook api_extensions
    export DEVSTACK_LOCALCONF=$(cat $LOCAL_CONF)
    $BASE/new/devstack-gate/devstack-vm-gate.sh
    ;;
*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
NETWORKING_SFC_PATH=$GATE_DEST/networking-sfc
GATE_HOOKS=$NETWORKING_SFC_PATH/networking_sfc/tests/contrib/hooks
DEVSTACK_PATH=$GATE_DEST/devstack
LOCAL_CONF=$DEVSTACK_PATH/local.conf


# Inject config from hook
function load_conf_hook {
    local hook="$1"
    config=$(cat $GATE_HOOKS/$hook)
    export DEVSTACK_LOCAL_CONFIG+="
# generated from hook '$hook'
${config}
"
}


case $VENV in
"dsvm-functional"|"dsvm-fullstack")
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=networking-sfc
    IS_GATE=True

    source $DEVSTACK_PATH/functions
    source $NETWORKING_SFC_PATH/devstack/lib/ovs

    source $NETWORKING_SFC_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing

    upgrade_ovs_if_necessary

    load_conf_hook iptables_verify
    load_conf_hook ovs
    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

#!/usr/bin/env bash

set -xe

# Drop a token that marks the build as coming from openstack infra
GATE_DEST=$BASE/new
DEVSTACK_PATH=$GATE_DEST/devstack
# for localrc_set
source $DEVSTACK_PATH/inc/ini-config


if [[ "$DEVSTACK_GATE_TOPOLOGY" == "multinode" ]] ; then
    local localrc_file=$DEVSTACK_PATH/local.conf
    localrc_set $localrc_file "NOVA_VNC_ENABLED" "True"
    # localrc_set $localrc_file "VNCSERVER_LISTEN" '0.0.0.0'
    local sub_localconf=$DEVSTACK_PATH/sub_local.conf
    localrc_set $sub_localconf "NOVA_VNC_ENABLED" "True"
    # localrc_set $localrc_file "VNCSERVER_LISTEN" '0.0.0.0'
fi


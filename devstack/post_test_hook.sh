#!/usr/bin/env bash

set -xe

GATE_DEST=$BASE/new
DEVSTACK_PATH=$GATE_DEST/devstack

source $DEVSTACK_PATH/functions

TEMPEST_CODE_DIR="$BASE/new/tempest"
TEMPEST_DATA_DIR="$BASE/data/tempest"
NETWORKING_SFC_DIR="$BASE/new/networking-sfc"

source $NETWORKING_SFC_DIR/devstack/devstackgaterc

owner=stack
sudo_env="TEMPEST_CONFIG_DIR=$TEMPEST_CODE_DIR/etc"

cd $TEMPEST_CODE_DIR
sudo chown -R $owner:stack $TEMPEST_CODE_DIR
sudo mkdir -p "$TEMPEST_DATA_DIR"
sudo chown -R $owner:stack $TEMPEST_DATA_DIR

echo "Running networking-sfc test suite"
sudo -H -u $owner $sudo_env tox -eall-plugin -- $DEVSTACK_GATE_TEMPEST_REGEX
sudo -H -u $owner $sudo_env tox -eall-plugin -- "^(?:networking_sfc\.tests\.tempest_plugin.tests.api).*$" --concurrency=0
sudo -H -u $owner $sudo_env tox -eall-plugin -- "^(?:networking_sfc\.tests\.tempest_plugin.tests.scenario).*$" --concurrency=0

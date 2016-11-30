# function definitions for networking-sfc devstack plugin
SFC_UPDATE_OVS=${SFC_UPDATE_OVS:-True}

function networking_sfc_install {
    setup_develop $NETWORKING_SFC_DIR
}

function _networking_sfc_install_server {
    _neutron_service_plugin_class_add $NEUTRON_FLOWCLASSIFIER_PLUGIN
    _neutron_service_plugin_class_add $NEUTRON_SFC_PLUGIN
    iniset $NEUTRON_CONF DEFAULT service_plugins $Q_SERVICE_PLUGIN_CLASSES
    iniadd $NEUTRON_CONF sfc drivers $NEUTRON_SFC_DRIVERS
    iniadd $NEUTRON_CONF flowclassifier drivers $NEUTRON_FLOWCLASSIFIER_DRIVERS
    neutron-db-manage --config-file $NEUTRON_CONF --config-file /$Q_PLUGIN_CONF_FILE --subproject networking-sfc upgrade head
}

function _networking_sfc_install_agent {
    iniset /$Q_PLUGIN_CONF_FILE agent extensions "sfc"
    _neutron_deploy_rootwrap_filters $NETWORKING_SFC_DIR
}

function networking_sfc_configure_common {
    if is_service_enabled q-svc; then
        _networking_sfc_install_server
    fi
    if is_service_enabled q-agt; then
        _networking_sfc_install_agent
    fi
}


if [[ "$1" == "stack" && "$2" == "install" ]]; then
    if is_service_enabled q-agt && [[ "$SFC_UPDATE_OVS" == "True" ]]; then
        source $NETWORKING_SFC_DIR/devstack/lib/ovs
        # The OVS_BRANCH variable is used by git checkout.
        OVS_BRANCH=v2.4.0
        remove_ovs_packages
        compile_ovs True /usr /var
        start_new_ovs
    fi

    # Perform installation of service source
    echo_summary "Installing networking-sfc"
    networking_sfc_install

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring networking-sfc"
    networking_sfc_configure_common
fi

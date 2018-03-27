# function definitions for networking-sfc devstack plugin

function networking_sfc_install {
    setup_develop $NETWORKING_SFC_DIR
}

function _networking_sfc_install_server {
    neutron_service_plugin_class_add $NEUTRON_FLOWCLASSIFIER_PLUGIN
    neutron_service_plugin_class_add $NEUTRON_SFC_PLUGIN
    iniadd $NEUTRON_CONF sfc drivers $NEUTRON_SFC_DRIVERS
    iniadd $NEUTRON_CONF flowclassifier drivers $NEUTRON_FLOWCLASSIFIER_DRIVERS
    neutron-db-manage --subproject networking-sfc upgrade head
}

function _networking_sfc_install_agent {
    source $NEUTRON_DIR/devstack/lib/l2_agent
    plugin_agent_add_l2_agent_extension sfc
    configure_l2_agent
}

function networking_sfc_configure_common {
    if is_service_enabled q-svc neutron-api; then
        _networking_sfc_install_server
    fi
    if is_service_enabled q-agt neutron-agent && [[ "$Q_AGENT" == "openvswitch" ]]; then
        _networking_sfc_install_agent
    fi
}


if [[ "$1" == "stack" && "$2" == "install" ]]; then
    # Perform installation of service source
    echo_summary "Installing networking-sfc"
    networking_sfc_install

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring networking-sfc"
    networking_sfc_configure_common
fi

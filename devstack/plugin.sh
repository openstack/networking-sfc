# function definitions for networking-sfc devstack plugin

function networking_sfc_install {
    setup_develop $NETWORKING_SFC_DIR
}

function networking_sfc_configure_common {
    _neutron_service_plugin_class_add $NEUTRON_FLOWCLASSIFIER_PLUGIN
    _neutron_service_plugin_class_add $NEUTRON_SFC_PLUGIN
    iniset $NEUTRON_CONF DEFAULT service_plugins $Q_SERVICE_PLUGIN_CLASSES
    iniadd $NEUTRON_CONF sfc drivers $NEUTRON_SFC_DRIVERS
    _neutron_deploy_rootwrap_filters $NETWORKING_SFC_DIR
    neutron-db-manage --config-file $NEUTRON_CONF --config-file /$Q_PLUGIN_CONF_FILE --subproject networking-sfc upgrade head
}


if [[ "$1" == "stack" && "$2" == "install" ]]; then
    # Perform installation of service source
    echo_summary "Installing networking-sfc"
    networking_sfc_install

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring networking-sfc"
    networking_sfc_configure_common
fi

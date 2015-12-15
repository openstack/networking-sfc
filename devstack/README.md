This directory contains the networking-sfc devstack plugin.  To
configure the networking sfc, in the [[local|localrc]] section,
you will need to enable the networking-sfc devstack plugin by
 editing the [[local|localrc]] section of your local.conf file.

1) Enable the plugin

To enable the plugin, add a line of the form:

    enable_plugin networking-sfc <GITURL> [GITREF]

where

    <GITURL> is the URL of a networking-sfc repository
    [GITREF] is an optional git ref (branch/ref/tag).  The default is
             master.

For example

    enable_plugin networking-sfc http://10.145.105.11/portchain

For more information, see the "Externally Hosted Plugins" section of
http://docs.openstack.org/developer/devstack/plugins.html.

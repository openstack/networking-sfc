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

 If you have already cloned the networking-sfc repository (which is
 useful when testing unmerged changes)

    enable_plugin networking-sfc /opt/stack/networking-sfc

 Or, if you want to pull the networking-sfc repository from Github
 and use a particular branch (for example Liberty, here)

    enable_plugin networking-sfc https://opendev.org/openstack/networking-sfc master

For more information, see the "Externally Hosted Plugins" section of
https://docs.openstack.org/devstack/latest/plugins.html .

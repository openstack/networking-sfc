# Copyright 2015 Futurewei. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


class SfcPluginContext():
    """SFC context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        self._plugin_context = plugin_context


class PortChainContext(SfcPluginContext):

    def __init__(self, plugin, plugin_context, portchain,
                 original_portchain=None):
        super().__init__(plugin, plugin_context)
        self._portchain = portchain
        self._original_portchain = original_portchain

    @property
    def current(self):
        return self._portchain

    @property
    def original(self):
        return self._original_portchain


class FlowClassifierContext(SfcPluginContext):
    def __init__(self, plugin, plugin_context, flowclassifier,
                 original_flowclassifier=None):
        super().__init__(plugin, plugin_context)
        self._flowclassifier = flowclassifier
        self._original_flowclassifier = original_flowclassifier

    @property
    def current(self):
        return self._flowclassifier

    @property
    def original(self):
        return self._original_flowclassifier


class PortPairContext(SfcPluginContext):
    def __init__(self, plugin, plugin_context, portpair,
                 original_portpair=None):
        super().__init__(plugin, plugin_context)
        self._portpair = portpair
        self._original_portpair = original_portpair

    @property
    def current(self):
        return self._portpair

    @property
    def original(self):
        return self._original_portpair


class PortPairGroupContext(SfcPluginContext):
    def __init__(self, plugin, plugin_context, portpairgroup,
                 original_portpairgroup=None):
        super().__init__(plugin, plugin_context)
        self._portpairgroup = portpairgroup
        self._original_portpairgroup = original_portpairgroup

    @property
    def current(self):
        return self._portpairgroup

    @property
    def original(self):
        return self._original_portpairgroup


class ServiceGraphContext(SfcPluginContext):

    def __init__(self, plugin, plugin_context, service_graph,
                 original_graph=None):
        super().__init__(plugin, plugin_context)
        self._service_graph = service_graph
        self._original_graph = original_graph

    @property
    def current(self):
        return self._service_graph

    @property
    def original(self):
        return self._original_graph

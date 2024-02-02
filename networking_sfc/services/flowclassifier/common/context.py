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


class FlowClassifierPluginContext():
    """Flow Classifier context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        self._plugin_context = plugin_context


class FlowClassifierContext(FlowClassifierPluginContext):

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

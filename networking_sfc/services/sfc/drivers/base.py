# Copyright 2015 Futurewei. All rights reserved.
# Copyright 2017 Intel Corporation.
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

import abc


class SfcDriverBaseLegacy(metaclass=abc.ABCMeta):
    """SFC Driver Base Class for legacy interface."""

    @abc.abstractmethod
    def create_port_chain(self, context):
        pass

    @abc.abstractmethod
    def update_port_chain(self, context):
        pass

    @abc.abstractmethod
    def create_port_pair(self, context):
        pass

    @abc.abstractmethod
    def update_port_pair(self, context):
        pass

    @abc.abstractmethod
    def create_port_pair_group(self, context):
        pass

    @abc.abstractmethod
    def update_port_pair_group(self, context):
        pass


class SfcDriverBase(SfcDriverBaseLegacy, metaclass=abc.ABCMeta):
    """SFC Driver Base Class."""

    def create_port_chain_precommit(self, context):
        pass

    def create_port_chain_postcommit(self, context):
        self.create_port_chain(context)

    @abc.abstractmethod
    def delete_port_chain(self, context):
        pass

    def delete_port_chain_precommit(self, context):
        pass

    def delete_port_chain_postcommit(self, context):
        pass

    def update_port_chain_precommit(self, context):
        pass

    def update_port_chain_postcommit(self, context):
        self.update_port_chain(context)

    def create_port_pair_precommit(self, context):
        pass

    def create_port_pair_postcommit(self, context):
        self.create_port_pair(context)

    @abc.abstractmethod
    def delete_port_pair(self, context):
        pass

    def delete_port_pair_precommit(self, context):
        pass

    def delete_port_pair_postcommit(self, context):
        pass

    def update_port_pair_precommit(self, context):
        pass

    def update_port_pair_postcommit(self, context):
        self.update_port_pair(context)

    def create_port_pair_group_precommit(self, context):
        pass

    def create_port_pair_group_postcommit(self, context):
        self.create_port_pair_group(context)

    @abc.abstractmethod
    def delete_port_pair_group(self, context):
        pass

    def delete_port_pair_group_precommit(self, context):
        pass

    def delete_port_pair_group_postcommit(self, context):
        pass

    def update_port_pair_group_precommit(self, context):
        pass

    def update_port_pair_group_postcommit(self, context):
        self.update_port_pair_group(context)

    def create_service_graph_precommit(self, context):
        pass

    def create_service_graph_postcommit(self, context):
        pass

    def update_service_graph_precommit(self, context):
        pass

    def update_service_graph_postcommit(self, context):
        pass

    def delete_service_graph_precommit(self, context):
        pass

    def delete_service_graph_postcommit(self, context):
        pass

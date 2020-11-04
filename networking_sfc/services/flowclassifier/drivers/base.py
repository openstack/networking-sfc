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

import abc


class FlowClassifierDriverBaseLegacy(metaclass=abc.ABCMeta):
    """Flow Classifier Driver Base Class for legacy driver interface"""

    @abc.abstractmethod
    def create_flow_classifier(self, context):
        pass

    @abc.abstractmethod
    def update_flow_classifier(self, context):
        pass


class FlowClassifierDriverBase(FlowClassifierDriverBaseLegacy,
                               metaclass=abc.ABCMeta):
    """Flow Classifier Driver Base Class."""

    @abc.abstractmethod
    def create_flow_classifier_precommit(self, context):
        pass

    def create_flow_classifier_postcommit(self, context):
        self.create_flow_classifier(context)

    @abc.abstractmethod
    def delete_flow_classifier(self, context):
        pass

    def delete_flow_classifier_precommit(self, context):
        pass

    def delete_flow_classifier_postcommit(self, context):
        pass

    def update_flow_classifier_precommit(self, context):
        pass

    def update_flow_classifier_postcommit(self, context):
        self.update_flow_classifier(context)

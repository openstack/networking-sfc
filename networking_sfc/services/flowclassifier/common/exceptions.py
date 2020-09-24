# Copyright 2015 Futurewei.  All rights reserved.
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
"""Exceptions used by FlowClassifier plugin and drivers."""

from neutron_lib import exceptions

from networking_sfc._i18n import _


class FlowClassifierDriverError(exceptions.NeutronException):
    """flow classifier driver call failed."""
    message = _("%(method)s failed.")


class FlowClassifierException(exceptions.NeutronException):
    """Base for flow classifier driver exceptions returned to user."""


class FlowClassifierBadRequest(exceptions.BadRequest, FlowClassifierException):
    """Base for flow classifier driver bad request exceptions."""
    message = _("%(message)s")

# Copyright 2017 Futurewei.  All rights reserved.
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
"""Exceptions used by SFC plugin and drivers."""

from neutron_lib import exceptions

from networking_sfc._i18n import _


class SfcDriverError(exceptions.NeutronException):
    """SFC driver call failed."""
    message = _("%(method)s failed.")


class SfcException(exceptions.NeutronException):
    """Base for SFC driver exceptions returned to user."""


class SfcBadRequest(exceptions.BadRequest, SfcException):
    """Base for SFC driver bad request exceptions returned to user."""
    message = _("%(message)s")


class SfcNoSubnetGateway(SfcDriverError):
    """No subnet gateway."""
    message = _("There is no %(type)s of ip prefix %(cidr)s.")


class SfcNoSuchSubnet(SfcDriverError):
    """No such subnet."""
    message = _("There is no %(type)s of %(cidr)s.")


class FlowClassifierInvalid(SfcDriverError):
    """Invalid flow classifier."""
    message = _("There is no %(type)s assigned.")

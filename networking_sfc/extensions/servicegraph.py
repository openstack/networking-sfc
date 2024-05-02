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

from abc import ABCMeta
from abc import abstractmethod

from neutron_lib.api import converters as lib_converters
from neutron_lib.api import extensions
from neutron_lib.api import validators as lib_validators
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as neutron_exc
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.api import extensions as neutron_ext
from neutron.api.v2 import resource_helper

from networking_sfc._i18n import _
from networking_sfc import extensions as sfc_extensions
from networking_sfc.extensions import sfc as ext_sfc


cfg.CONF.import_opt('api_extensions_path', 'neutron.common.config')
neutron_ext.append_api_extensions_path(sfc_extensions.__path__)

SG_EXT = "service_graph"
SG_PREFIX = ext_sfc.SFC_PREFIX

SERVICE_GRAPH = 'service_graph'
SERVICE_GRAPHS = '%ss' % SERVICE_GRAPH


# NOTE(scsnow): move to neutron-lib
def validate_list_of_allowed_values(data, allowed_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        return msg

    illegal_values = set(data) - set(allowed_values)
    if illegal_values:
        msg = _("Illegal values in a list: %s") % ', '.join(illegal_values)
        return msg


lib_validators.validators['type:list_of_allowed_values'] = \
    validate_list_of_allowed_values


class InvalidUUID(neutron_exc.InvalidInput):
    message = _(
        "An invalid UUID was specified: %%(error_message)s. "
        "Make sure only valid UUIDs are provided.")


class ServiceGraphInvalidPortChains(neutron_exc.InUse):
    message = _("Some of the Port Chain(s): %(port_chains)s, "
                "are already in use by a Service Graph.")


class ServiceGraphPortChainInUse(neutron_exc.InUse):
    message = _("Port Chain %(id)s in use.")


class ServiceGraphNotFound(neutron_exc.NotFound):
    message = _("Service Graph %(id)s not found.")


class ServiceGraphLoopDetected(neutron_exc.InvalidInput):
    message = _("Service Graph defined contains at least one port chain loop.")


class ServiceGraphInconsistentEncapsulation(neutron_exc.InvalidInput):
    message = _("Service Graph may only connect port-chains "
                "sharing the same correlation.")


class ServiceGraphImpossibleBranching(neutron_exc.InvalidInput):
    message = _("Service Graphs require source (branching) and destination "
                "port pair groups (their PPs) to have correlation enabled.")


class ServiceGraphFlowClassifierInConflict(neutron_exc.InvalidInput):
    message = _("Flow Classifier %(fc1_id)s conflicts with Flow Classifier "
                "%(fc2_id)s on one of the branching points being created.")


class ServiceGraphPortChainInConflict(neutron_exc.InvalidInput):
    message = _("Port Chain %(pc_id)s is duplicated on one "
                "of the branching points being created.")


def normalize_service_graph(port_chains):
    port_chains = lib_converters.convert_none_to_empty_dict(port_chains)
    for key in port_chains:
        if uuidutils.is_uuid_like(key):
            for val in port_chains[key]:
                if not uuidutils.is_uuid_like(val):
                    raise InvalidUUID(
                        error_message='UUID of destination Port-Chain '
                                      'is invalid: %s.' % key)
        else:
            raise InvalidUUID(
                error_message='UUID of source Port-Chain'
                              'is invalid: %s.' % key)
    return port_chains


RESOURCE_ATTRIBUTE_MAP = {
    SERVICE_GRAPHS: {
        'id': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None},
            'primary_key': True},
        'name': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': '',
            'validate': {'type:string': db_const.NAME_FIELD_SIZE}},
        'description': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': '',
            'validate': {'type:string': db_const.DESCRIPTION_FIELD_SIZE}},
        'project_id': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:string': db_const.PROJECT_ID_FIELD_SIZE},
            'required_by_policy': True},
        'port_chains': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:dict': None},
            'convert_to': normalize_service_graph}
    }
}

service_graph_quota_opts = [
    cfg.IntOpt('quota_service_graphs',
               default=10,
               help=_('maximum number of Service Graphs per project. '
                      'a negative value means unlimited.'))
]

cfg.CONF.register_opts(service_graph_quota_opts, 'QUOTAS')


class Servicegraph(extensions.ExtensionDescriptor):
    """Service Graph extension."""

    @classmethod
    def get_name(cls):
        return "Service Graph"

    @classmethod
    def get_alias(cls):
        return SG_EXT

    @classmethod
    def get_description(cls):
        return "Service Graph extension."

    @classmethod
    def get_updated(cls):
        return "2017-09-20T00:00:00-00:00"

    @classmethod
    def update_attributes_map(cls, extended_attributes,
                              extension_attrs_map=None):
        super().update_attributes_map(
            extended_attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        plural_mappings['service_graphs'] = 'service_graph'
        return resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            ext_sfc.SFC_EXT,
            register_quota=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        return {}


class ServiceGraphPluginBase(metaclass=ABCMeta):

    def get_plugin_type(self):
        return SG_EXT

    def get_plugin_description(self):
        return 'SFC Service Graphs extension for networking-sfc.'

    @abstractmethod
    def create_service_graph(self, context, service_graph):
        pass

    @abstractmethod
    def update_service_graph(self, context, id, service_graph):
        pass

    @abstractmethod
    def delete_service_graph(self, context, id):
        pass

    @abstractmethod
    def get_service_graphs(self, context, filters=None,
                           fields=None, sorts=None, limit=None,
                           marker=None, page_reverse=False):
        pass

    @abstractmethod
    def get_service_graph(self, context, id, fields=None):
        pass

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

from abc import ABCMeta
from abc import abstractmethod

import six

from neutron_lib.api import converters as lib_converters
from neutron_lib import exceptions as neutron_exc
from oslo_config import cfg

from neutron.api import extensions as neutron_ext
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.services import service_base

from networking_sfc._i18n import _
from networking_sfc import extensions

cfg.CONF.import_opt('api_extensions_path', 'neutron.common.config')
neutron_ext.append_api_extensions_path(extensions.__path__)

SFC_EXT = "sfc"
SFC_PREFIX = "/sfc"

SUPPORTED_LB_FIELDS = [
    "eth_src", "eth_dst", "ip_src", "ip_dst",
    "tcp_src", "tcp_dst", "udp_src", "udp_dst"
]


class InvalidLBField(neutron_exc.InvalidInput):
    message = _("Unknown lb field %(field)s.")


def normalize_lb_fields(lb_fields):
    lb_fields = lib_converters.convert_none_to_empty_list(lb_fields)
    for field in lb_fields:
        if field not in SUPPORTED_LB_FIELDS:
            raise InvalidLBField(
                field=field)
    return lb_fields


SUPPORTED_CHAIN_PARAMETERS = {
    'correlation': {
        'allow_post': True,
        'default': 'mpls',
        'validate': {'type:values': ['mpls']}
    }
}
SUPPORTED_SF_PARAMETERS = {
    'correlation': {
        'allow_post': True,
        'default': None,
        'validate': {'type:values': [None]}
    },
    'weight': {
        'allow_post': True,
        'default': 1,
        'validate': {'type:non_negative': None},
        'convert_to': lib_converters.convert_to_int
    }
}
SUPPORTED_PPG_PARAMETERS = {
    'lb_fields': {
        'allow_post': True,
        'default': None,
        'validate': {'type:list_of_unique_strings': None},
        'convert_to': normalize_lb_fields
    }
}
MAX_CHAIN_ID = 65535


# Port Chain Exceptions
class PortChainNotFound(neutron_exc.NotFound):
    message = _("Port Chain %(id)s not found.")


class PortChainUnavailableChainId(neutron_exc.InvalidInput):
    message = _("Port Chain %(id)s no available chain id.")


class PortChainFlowClassifierInConflict(neutron_exc.InvalidInput):
    message = _("Flow Classifier %(fc_id)s conflicts with "
                "Flow Classifier %(pc_fc_id)s in port chain %(pc_id)s.")


class PortChainChainIdInConflict(neutron_exc.InvalidInput):
    message = _("Chain id %(chain_id)s conflicts with "
                "Chain id in port chain %(pc_id)s.")


class InvalidChainParameter(neutron_exc.InvalidInput):
    message = _(
        "Invalid chain parameter: %%(error_message)s. "
        "Supported chain parameters are %(supported_paramters)s."
    ) % {'supported_paramters': SUPPORTED_CHAIN_PARAMETERS}


class InvalidServiceFunctionParameter(neutron_exc.InvalidInput):
    message = _(
        "Invalid Service function parameter: %%(error_message)s. "
        "Supported service function parameters are %(supported_paramters)s."
    ) % {'supported_paramters': SUPPORTED_SF_PARAMETERS}


class InvalidPortPairGroupParameter(neutron_exc.InvalidInput):
    message = _(
        "Invalid port pair group parameter: %%(error_message)s. "
        "Supported port pair group parameters are %(supported_paramters)s."
    ) % {'supported_paramters': SUPPORTED_PPG_PARAMETERS}


class PortPairGroupNotSpecified(neutron_exc.InvalidInput):
    message = _("Port Pair Group is not specified in Port Chain.")


class InvalidPortPairGroups(neutron_exc.InUse):
    message = _("Port Pair Group(s) %(port_pair_groups)s in use by "
                "Port Chain %(port_chain)s.")


class PortPairPortNotFound(neutron_exc.NotFound):
    message = _("Port Pair port %(id)s not found.")


class PortPairIngressEgressDifferentHost(neutron_exc.InvalidInput):
    message = _("Port Pair ingress port %(ingress)s and"
                "egress port %(egress)s not in the same host.")


class PortPairIngressNoHost(neutron_exc.InvalidInput):
    message = _("Port Pair ingress port %(ingress)s does not "
                "belong to a host.")


class PortPairEgressNoHost(neutron_exc.InvalidInput):
    message = _("Port Pair egress port %(egress)s does not "
                "belong to a host.")


class PortPairIngressEgressInUse(neutron_exc.InvalidInput):
    message = _("Port Pair with ingress port %(ingress)s "
                "and egress port %(egress)s is already used by "
                "another Port Pair %(id)s.")


class PortPairNotFound(neutron_exc.NotFound):
    message = _("Port Pair %(id)s not found.")


class PortPairGroupNotFound(neutron_exc.NotFound):
    message = _("Port Pair Group %(id)s not found.")


class PortPairGroupInUse(neutron_exc.InUse):
    message = _("Port Pair Group %(id)s in use.")


class PortPairInUse(neutron_exc.InUse):
    message = _("Port Pair %(id)s in use.")


def normalize_string(value):
    if value is None:
        return ''
    return value


def normalize_port_pair_groups(port_pair_groups):
    port_pair_groups = lib_converters.convert_to_list(port_pair_groups)
    if not port_pair_groups:
        raise PortPairGroupNotSpecified()
    return port_pair_groups


def normalize_chain_parameters(parameters):
    parameters = lib_converters.convert_none_to_empty_dict(parameters)
    for key in parameters:
        if key not in SUPPORTED_CHAIN_PARAMETERS:
            raise InvalidChainParameter(
                error_message='Unknown key %s.' % key)
    try:
        attr.fill_default_value(
            SUPPORTED_CHAIN_PARAMETERS, parameters)
        attr.convert_value(
            SUPPORTED_CHAIN_PARAMETERS, parameters)
    except ValueError as error:
        raise InvalidChainParameter(error_message=str(error))
    return parameters


def normalize_sf_parameters(parameters):
    parameters = lib_converters.convert_none_to_empty_dict(parameters)
    for key in parameters:
        if key not in SUPPORTED_SF_PARAMETERS:
            raise InvalidServiceFunctionParameter(
                error_message='Unknown key %s.' % key)
    try:
        attr.fill_default_value(
            SUPPORTED_SF_PARAMETERS, parameters)
        attr.convert_value(
            SUPPORTED_SF_PARAMETERS, parameters)
    except ValueError as error:
        raise InvalidServiceFunctionParameter(error_message=str(error))
    return parameters


def normalize_ppg_parameters(parameters):
    parameters = lib_converters.convert_none_to_empty_dict(parameters)
    for key in parameters:
        if key not in SUPPORTED_PPG_PARAMETERS:
            raise InvalidPortPairGroupParameter(
                error_message='Unknown key %s.' % key)
    try:
        attr.fill_default_value(
            SUPPORTED_PPG_PARAMETERS, parameters)
        attr.convert_value(
            SUPPORTED_PPG_PARAMETERS, parameters)
    except ValueError as error:
        raise InvalidPortPairGroupParameter(error_message=str(error))
    return parameters


RESOURCE_ATTRIBUTE_MAP = {
    'port_pairs': {
        'id': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None},
            'primary_key': True},
        'name': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': attr.NAME_MAX_LEN},
            'convert_to': normalize_string},
        'description': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': attr.DESCRIPTION_MAX_LEN},
            'convert_to': normalize_string},
        'tenant_id': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
            'required_by_policy': True},
        'ingress': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None}},
        'egress': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None}},
        'service_function_parameters': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:dict': None},
            'convert_to': normalize_sf_parameters},
    },
    'port_chains': {
        'id': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None},
            'primary_key': True},
        'chain_id': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': 0,
            'validate': {'type:range': (0, MAX_CHAIN_ID)},
            'convert_to': lib_converters.convert_to_int},
        'name': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': attr.NAME_MAX_LEN},
            'convert_to': normalize_string},
        'description': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': attr.DESCRIPTION_MAX_LEN},
            'convert_to': normalize_string},
        'tenant_id': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
            'required_by_policy': True},
        'port_pair_groups': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True,
            'validate': {'type:uuid_list': None},
            'convert_to': normalize_port_pair_groups},
        'flow_classifiers': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:uuid_list': None},
            'convert_to': lib_converters.convert_to_list},
        'chain_parameters': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:dict': None},
            'convert_to': normalize_chain_parameters}
    },
    'port_pair_groups': {
        'id': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:uuid': None},
            'primary_key': True},
        'group_id': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True},
        'name': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': attr.NAME_MAX_LEN},
            'convert_to': normalize_string},
        'description': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:string': attr.DESCRIPTION_MAX_LEN},
            'convert_to': normalize_string},
        'tenant_id': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True,
            'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
            'required_by_policy': True},
        'port_pairs': {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'validate': {'type:uuid_list': None},
            'convert_to': lib_converters.convert_none_to_empty_list},
        'port_pair_group_parameters': {
            'allow_post': True, 'allow_put': False,
            'is_visible': True, 'default': None,
            'validate': {'type:dict': None},
            'convert_to': normalize_ppg_parameters},
    },
}

sfc_quota_opts = [
    cfg.IntOpt('quota_port_chain',
               default=10,
               help=_('Maximum number of port chains per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_port_pair_group',
               default=10,
               help=_('maximum number of port pair group per tenant. '
                      'a negative value means unlimited.')),
    cfg.IntOpt('quota_port_pair',
               default=100,
               help=_('maximum number of port pair per tenant. '
                      'a negative value means unlimited.'))
]

cfg.CONF.register_opts(sfc_quota_opts, 'QUOTAS')


class Sfc(neutron_ext.ExtensionDescriptor):
    """Service Function Chain extension."""

    @classmethod
    def get_name(cls):
        return "Service Function Chaining"

    @classmethod
    def get_alias(cls):
        return SFC_EXT

    @classmethod
    def get_description(cls):
        return "Service Function Chain extension."

    @classmethod
    def get_plugin_interface(cls):
        return SfcPluginBase

    @classmethod
    def get_updated(cls):
        return "2015-10-05T10:00:00-00:00"

    def update_attributes_map(self, attributes):
        super(Sfc, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        plural_mappings['sfcs'] = 'sfc'
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            SFC_EXT,
            register_quota=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(ABCMeta)
class SfcPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return SFC_EXT

    def get_plugin_type(self):
        return SFC_EXT

    def get_plugin_description(self):
        return 'SFC service plugin for service chaining.'

    @abstractmethod
    def create_port_chain(self, context, port_chain):
        pass

    @abstractmethod
    def update_port_chain(self, context, id, port_chain):
        pass

    @abstractmethod
    def delete_port_chain(self, context, id):
        pass

    @abstractmethod
    def get_port_chains(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        pass

    @abstractmethod
    def get_port_chain(self, context, id, fields=None):
        pass

    @abstractmethod
    def create_port_pair_group(self, context, port_pair_group):
        pass

    @abstractmethod
    def update_port_pair_group(self, context, id, port_pair_group):
        pass

    @abstractmethod
    def delete_port_pair_group(self, context, id):
        pass

    @abstractmethod
    def get_port_pair_groups(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        pass

    @abstractmethod
    def get_port_pair_group(self, context, id, fields=None):
        pass

    @abstractmethod
    def create_port_pair(self, context, port_pair):
        pass

    @abstractmethod
    def update_port_pair(self, context, id, port_pair):
        pass

    @abstractmethod
    def delete_port_pair(self, context, id):
        pass

    @abstractmethod
    def get_port_pairs(self, context, filters=None, fields=None,
                       sorts=None, limit=None, marker=None,
                       page_reverse=False):
        pass

    @abstractmethod
    def get_port_pair(self, context, id, fields=None):
        pass

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


from neutronclient.common import exceptions
from neutronclient.neutron import v2_0 as neutronV20

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine.resources.openstack.neutron import neutron
from heat.engine import support
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NuageSecGroupConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'security_group', value)


class NuageRedirectTarget(neutron.NeutronResource):
    """
    A resource representing Nuage Redirect Target in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME, DESCRIPTION, INSERTION_MODE, SUBNET, ROUTER, REDUNDANCY,
    ) = (
        'name', 'description', 'insertion_mode', 'subnet_id',
        'router_id', 'redundancy_enabled',
    )

    ATTRIBUTES = (
        NAME_ATTR, DESCR_ATTR, INSERTION_MODE_ATTR,
        REDUNDANCY_ATTR, SHOW,
    ) = (
        'name', 'description', 'insertion_mode',
        'redundancy_enabled', 'show',
    )

    L3, VIRTUAL_WIRE = ('L3', 'VIRTUAL_WIRE')

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Redirect Target'),
            required=True,
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the Redirect Target'),
            required=False,
            update_allowed=True
        ),
        INSERTION_MODE: properties.Schema(
            properties.Schema.STRING,
            _('Service Insertion Type'),
            required=True,
            constraints=[
                constraints.AllowedValues([L3, VIRTUAL_WIRE]),
            ],
            update_allowed=True
        ),
        SUBNET: properties.Schema(
            properties.Schema.STRING,
            _('Subnet this Redirect Target should be created for'),
            constraints=[
                constraints.CustomConstraint('neutron.subnet')
            ],
            required=False,
            update_allowed=False,
        ),
        ROUTER: properties.Schema(
            properties.Schema.STRING,
            _('Router this Redirect Target should be created for'),
            constraints=[
                constraints.CustomConstraint('neutron.router')
            ],
            required=False,
            update_allowed=False,
        ),
        REDUNDANCY: properties.Schema(
            properties.Schema.STRING,
            _('Allow redundant Appliances'),
            constraints=[
                constraints.AllowedValues(['True', 'False']),
            ],
            required=False,
            default='False',
            update_allowed=True,
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Redirect Target'),
        ),
        DESCR_ATTR: attributes.Schema(
            _('Description of the Redirect Target'),
        ),
        INSERTION_MODE_ATTR: attributes.Schema(
            _('Service Insertion Type'),
        ),
        REDUNDANCY_ATTR: attributes.Schema(
            _('Allow redundant Appliances'),
        ),
        SHOW: attributes.Schema(
            _('All attributes'),
        ),
    }

    def _get_client(self):
        return self.neutron()

    def _validate_insertion_type(self):
        insertion_type = self.properties.get(self.INSERTION_MODE)
        redcy = self.properties.get(self.REDUNDANCY)
        if redcy is True and insertion_type in [self.VIRTUAL_WIRE]:
            msg = _('redundand appliances support is not applicable for '
                    'specified "insertion_mode"')
            raise exception.StackValidationFailed(message=msg)

    def _validate_domain(self):
        router = self.properties.get(self.ROUTER)
        subnet = self.properties.get(self.SUBNET)
        insertion_type = self.properties.get(self.INSERTION_MODE)
        if router and subnet:
            raise exception.ResourcePropertyConflict(self.ROUTER, self.SUBNET)
        if subnet and insertion_type in [self.L3]:
            msg = _('specified "insertion_mode" is not applicable for '
                    'isolated subnet')
            raise exception.StackValidationFailed(message=msg)

    def validate(self):
        super(NuageRedirectTarget, self).validate()
        self._validate_domain()
        self._validate_insertion_type()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        rt = self._get_client().create_nuage_redirect_target(
            {'nuage_redirect_target': props})['nuage_redirect_target']
        self.resource_id_set(rt['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_nuage_redirect_target(self.resource_id)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_nuage_redirect_target(
            self.resource_id)['nuage_redirect_target']


class NuageRedirectTargetVIP(neutron.NeutronResource):
    """
    A resource representing Nuage Redirect Target Virtual IP in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        SUBNET, REDIRECT_TARGET_ID, VIP,
    ) = (
        'subnet_id', 'redirect_target_id', 'virtual_ip_address',
    )

    ATTRIBUTES = (
    )

    properties_schema = {
        SUBNET: properties.Schema(
            properties.Schema.STRING,
            _('Subnet this Redirect Target should be created for'),
            constraints=[
                constraints.CustomConstraint('neutron.subnet')
            ],
            required=False,
            update_allowed=False,
        ),
        REDIRECT_TARGET_ID: properties.Schema(
            properties.Schema.STRING,
            _('Name or ID of the Redirect Target'),
            required=True,
            update_allowed=False,
        ),
        VIP: properties.Schema(
            properties.Schema.STRING,
            _('Virtual IP'),
            required=False,
            update_allowed=False,
        ),
    }

    attributes_schema = {
    }

    def _get_client(self):
        return self.neutron()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        vip = self._get_client().create_nuage_redirect_target_vip(
            {'nuage_redirect_target_vip': props})['nuage_redirect_target_vip']
        self.resource_id_set(vip['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_nuage_redirect_target_vip(self.resource_id)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)


class NuageRedirectTargetRule(neutron.NeutronResource):
    """
    A resource representing Nuage Redirect Target Rule in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        REDIRECT_TARGET_ID, PROTO, ACTION, PRIORITY, ORIGIN_GROUP_ID,
        REMOTE_GROUP_ID, PORT_RANGE_MIN, PORT_RANGE_MAX, REMOTE_IP_PREFIX,
    ) = (
        'redirect_target_id', 'protocol', 'action', 'priority',
        'origin_group_id', 'remote_group_id', 'port_range_min',
        'port_range_max', 'remote_ip_prefix',
    )

    ATTRIBUTES = (
        REDIRECT_TARGET_ID_ATTR, PROTO_ATTR, ACTION_ATTR, PRIORITY_ATTR,
        ORIGIN_GROUP_ID_ATTR, REMOTE_GROUP_ID_ATTR, PORT_RANGE_MIN_ATTR,
        PORT_RANGE_MAX_ATTR, REMOTE_IP_PREFIX_ATTR,
    ) = (
        'redirect_target_id', 'protocol', 'action', 'priority',
        'origin_group_id', 'remote_group_id', 'port_range_min',
        'port_range_max', 'remote_ip_prefix',
    )

    tcp, TCP, udp, UDP, icmp, ICMP = (
        'tcp', 'TCP', 'udp', 'UDP', 'icmp', 'ICMP')

    FORWARD, REDIRECT = ('FORWARD', 'REDIRECT')

    properties_schema = {
        REDIRECT_TARGET_ID: properties.Schema(
            properties.Schema.STRING,
            _('Name or ID of the Redirect Target'),
            required=True,
            update_allowed=False,
        ),
        PROTO: properties.Schema(
            properties.Schema.STRING,
            _('Protocol'),
            required=True,
            update_allowed=False,
        ),
        ACTION: properties.Schema(
            properties.Schema.STRING,
            _('Action associated with matched packets'),
            required=True,
            update_allowed=False,
            constraints=[
                constraints.AllowedValues([FORWARD, REDIRECT]),
            ],
        ),
        PRIORITY: properties.Schema(
            properties.Schema.NUMBER,
            _('Priority of the entry'),
            required=False,
            update_allowed=True,
        ),
        ORIGIN_GROUP_ID: properties.Schema(
            properties.Schema.STRING,
            _('Origin location'),
            constraints=[
                constraints.CustomConstraint('redirect_target.security_group'),
            ],
            required=True,
            update_allowed=False,
        ),
        REMOTE_GROUP_ID: properties.Schema(
            properties.Schema.STRING,
            _('Remote location'),
            constraints=[
                constraints.CustomConstraint('redirect_target.security_group'),
            ],
            required=False,
            update_allowed=False,
        ),
        PORT_RANGE_MIN: properties.Schema(
            properties.Schema.NUMBER,
            _('Destination start port to match'),
            required=False,
            update_allowed=True,
        ),
        PORT_RANGE_MAX: properties.Schema(
            properties.Schema.NUMBER,
            _('Destination end port to match'),
            required=False,
            update_allowed=True,
        ),
        REMOTE_IP_PREFIX: properties.Schema(
            properties.Schema.STRING,
            _('Remote CIDR to match'),
            required=False,
            update_allowed=False,
        ),
    }

    attributes_schema = {
        REDIRECT_TARGET_ID_ATTR: attributes.Schema(
            _('Name or ID of the Redirect Target'),
        ),
        PROTO_ATTR: attributes.Schema(
            _('Protocol'),
        ),
        ACTION_ATTR: attributes.Schema(
            _('Action'),
        ),
        PRIORITY_ATTR: attributes.Schema(
            _('Priority'),
        ),
        ORIGIN_GROUP_ID_ATTR: attributes.Schema(
            _('Origin location'),
        ),
        REMOTE_GROUP_ID_ATTR: attributes.Schema(
            _('Remote location'),
        ),
        PORT_RANGE_MIN_ATTR: attributes.Schema(
            _('Destination start port to match'),
        ),
        PORT_RANGE_MAX_ATTR: attributes.Schema(
            _('Destination end port to match'),
        ),
        REMOTE_IP_PREFIX_ATTR: attributes.Schema(
            _('Remote CIDR to match'),
        ),
    }

    def _get_client(self):
        return self.neutron()

    def _validate_port_range(self):
        proto = self.properties.get(self.PROTO)
        port_min = self.properties.get(self.PORT_RANGE_MIN)
        port_max = self.properties.get(self.PORT_RANGE_MAX)
        if (
            (port_min is not None or port_max is not None) and
            (proto not in [self.TCP, self.tcp, self.UDP, self.udp, '6', '17'])
        ):
            msg = _('port-range is not applicable for specified Protocol')
            raise exception.StackValidationFailed(message=msg)

    def _prepare_rt_rule_properties(self, props):
        props[self.ORIGIN_GROUP_ID] = self.client_plugin(
        ).get_secgroup_uuids([props.get(self.ORIGIN_GROUP_ID)])[0]
        props[self.REMOTE_GROUP_ID] = self.client_plugin(
        ).get_secgroup_uuids([props.get(self.REMOTE_GROUP_ID)])[0]

    def validate(self):
        super(NuageRedirectTargetRule, self).validate()
        self._validate_port_range()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        self._prepare_rt_rule_properties(props)

        rtr = self._get_client().create_nuage_redirect_target_rule(
            {'nuage_redirect_target_rule': props}
        )['nuage_redirect_target_rule']
        self.resource_id_set(rtr['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_nuage_redirect_target_rule(self.resource_id)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_nuage_redirect_target_rule(
            self.resource_id)['nuage_redirect_target_rule']


def resource_mapping():
    return {
        'Nuage::Neutron::RedirectTarget': NuageRedirectTarget,
        'Nuage::Neutron::RedirectTargetVIP': NuageRedirectTargetVIP,
        'Nuage::Neutron::RedirectTargetRule': NuageRedirectTargetRule,
    }


def constraint_mapping():
    return {
        'redirect_target.security_group': NuageSecGroupConstraint
    }

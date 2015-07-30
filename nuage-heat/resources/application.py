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


class ApplicationDomainConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException,)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'application_domain', value)


class ApplicationConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException,)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'application', value)


class ApplicationTierConstraint(constraints.BaseCustomConstraint):

    expected_exceptions = (exceptions.NeutronClientException,)

    def validate_with_client(self, client, value):
        neutron_client = client.client('neutron')
        neutronV20.find_resourceid_by_id(
            neutron_client, 'tier', value)


class NuageApplicationDomain(neutron.NeutronResource):
    """
    A resource representing Nuage Application Domain in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
    ) = (
        'name',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        DEPLOYMENT_POLICY_ATTR,
        TENANT_ATTR,
        SHOW,
    ) = (
        'name',
        'applicationDeploymentPolicy',
        'tenant_id',
        'show',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Application Domain'),
            required=True,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Application Domain')
        ),
        DEPLOYMENT_POLICY_ATTR: attributes.Schema(
            _('Deployment Policy for application'),
        ),
        TENANT_ATTR: attributes.Schema(
            _('Id of the tenant who is allowed to use this domain.')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def validate(self):
        super(NuageApplicationDomain, self).validate()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        app_domain = self._get_client().create_application_domain(
            {'application_domain': props})['application_domain']
        self.resource_id_set(app_domain['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_application_domain(self.resource_id)
        except Exception as ex:
            self.client_plugin('neutron').ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_application_domain(
            self.resource_id)['application_domain']


class NuageApplication(neutron.NeutronResource):
    """
    A resource representing Nuage Application in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
        APP_DOMAIN,
        DESCRIPTION,
    ) = (
        'name',
        'applicationdomain_id',
        'description',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        ASSOC_DOMAIN_ATTR,
        TENANT_ATTR,
        SHOW,
    ) = (
        'name',
        'associateddomainid',
        'tenant_id',
        'show',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Application'),
            required=True,
            update_allowed=False
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('User defined description of the Application'),
            required=True,
            update_allowed=False
        ),
        APP_DOMAIN: properties.Schema(
            properties.Schema.STRING,
            _('ID or Name of the deployment Application Domain'),
            constraints=[
                constraints.CustomConstraint(
                    'nuage_application.applicationdomain')
            ],
            required=True,
            update_allowed=False
        ),

    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Application Domain')
        ),
        ASSOC_DOMAIN_ATTR: attributes.Schema(
            _('ID of the deployment domain of the Application'),
        ),
        TENANT_ATTR: attributes.Schema(
            _('Id of the tenant who is allowed to use this domain.')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def validate(self):
        super(NuageApplication, self).validate()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        app = self._get_client().create_application(
            {'application': props})['application']
        self.resource_id_set(app['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_application(self.resource_id)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_application(
            self.resource_id)['application']


class NuageApplicationTier(neutron.NeutronResource):
    """
    A resource representing Nuage Application Tier in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
        APP_ID,
        TYPE,
        CIDR,
        FIP_POOL_ID,
    ) = (
        'name',
        'app_id',
        'type',
        'cidr',
        'fip_pool_id',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        ASSOC_APP_ATTR,
        TYPE_ATTR,
        TENANT_ATTR,
        SHOW,
    ) = (
        'name',
        'associatedappid',
        'type',
        'tenant_id',
        'show',
    )

    STANDARD, NETWORK_MACRO, APPLICATION, APPLICATION_EXTENDED_NETWORK = (
        'STANDARD', 'NETWORK_MACRO', 'APPLICATION',
        'APPLICATION_EXTENDED_NETWORK')

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Application Tier'),
            required=True,
            update_allowed=False
        ),
        APP_ID: properties.Schema(
            properties.Schema.STRING,
            _('ID or Application this Tier will belong to'),
            constraints=[
                constraints.CustomConstraint('nuage_application.application')
            ],
            required=True,
            update_allowed=False
        ),
        TYPE: properties.Schema(
            properties.Schema.STRING,
            _('Type of the Tier to create'),
            required=True,
            constraints=[
                constraints.AllowedValues([STANDARD,
                                           NETWORK_MACRO,
                                           APPLICATION,
                                           APPLICATION_EXTENDED_NETWORK]),
            ],
            update_allowed=False
        ),
        CIDR: properties.Schema(
            properties.Schema.STRING,
            _('CIDR of the Tier'),
            required=False,
            update_allowed=False
        ),
        FIP_POOL_ID: properties.Schema(
            properties.Schema.STRING,
            _('ID of the FIP pool'),
            required=False,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Application Domain')
        ),
        ASSOC_APP_ATTR: attributes.Schema(
            _('ID of the Application this Tier belongs to'),
        ),
        TYPE_ATTR: attributes.Schema(
            _('Type of the tier')
        ),
        TENANT_ATTR: attributes.Schema(
            _('Id of the tenant owning this Tier')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def _validate_type(self):
        tier_type = self.properties.get(self.TYPE)
        cidr = self.properties.get(self.CIDR)
        fip_pool = self.properties.get(self.FIP_POOL_ID)
        if cidr and tier_type in [self.APPLICATION,
                                  self.APPLICATION_EXTENDED_NETWORK]:
            msg = _('"cidr" property  is not applicable for '
                    'specified Tier type')
            raise exception.StackValidationFailed(message=msg)
        if not cidr and tier_type in [self.STANDARD, self.NETWORK_MACRO]:
            msg = _('"cidr" property is required for '
                    'specified Tier type')
            raise exception.StackValidationFailed(message=msg)
        if fip_pool and tier_type not in [self.STANDARD]:
            msg = _('"fip_pool_id" property is not applicable for '
                    'specified Tier type')
            raise exception.StackValidationFailed(message=msg)

    def validate(self):
        super(NuageApplicationTier, self).validate()
        self._validate_type()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        tier = self._get_client().create_tier(
            {'tier': props})['tier']
        self.resource_id_set(tier['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_tier(self.resource_id)
        except Exception as ex:
            self.client_plugin().ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_tier(self.resource_id)['tier']


class NuageApplicationService(neutron.NeutronResource):
    """
    A resource representing Nuage Application Service in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
        DESCRIPTION,
        DIRECTION,
        PROTO,
        SRC_PORT,
        DEST_PORT,
        ETHERTYPE,
        DSCP,
    ) = (
        'name',
        'description',
        'direction',
        'protocol',
        'src_port',
        'dest_port',
        'ethertype',
        'dscp',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        DIRECTION_ATTR,
        PROTO_ATTR,
        SRC_PORT_ATTR,
        DEST_PORT_ATTR,
        DSCP_ATTR,
        TENANT_ATTR,
        SHOW,
    ) = (
        'name',
        'direction',
        'protocol',
        'src_port',
        'dest_port',
        'dscp',
        'tenant_id',
        'show',
    )

    BIDIRECTIONAL, REFLEXIVE, UNIDIRECTIONAL = (
        'BIDIRECTIONAL', 'REFLEXIVE', 'UNIDIRECTIONAL')

    IPV4, IPV6, ARP = (
        'ipv4', 'ipv6', 'arp')

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Application Service'),
            required=True,
            update_allowed=False
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('User defined description of the Application Service'),
            required=False,
            update_allowed=False
        ),
        DIRECTION: properties.Schema(
            properties.Schema.STRING,
            _('Direction of the Application Service'),
            default=REFLEXIVE,
            constraints=[
                constraints.AllowedValues([BIDIRECTIONAL,
                                           REFLEXIVE,
                                           UNIDIRECTIONAL]),
            ],
            update_allowed=False
        ),
        PROTO: properties.Schema(
            properties.Schema.STRING,
            _('Protocol used by Application Service. \
              Either proto number or mnemonic can be used'),
            required=True,
            update_allowed=False
        ),
        SRC_PORT: properties.Schema(
            properties.Schema.STRING,
            _('Source port. Value can be either \
              * or single port number or a port range'),
            required=False,
            update_allowed=False
        ),
        DEST_PORT: properties.Schema(
            properties.Schema.STRING,
            _('Destination port. Value can be either \
              * or single port number or a port range'),
            required=False,
            update_allowed=False
        ),
        ETHERTYPE: properties.Schema(
            properties.Schema.STRING,
            _('Ethertype'),
            required=False,
            constraints=[
                constraints.AllowedValues([IPV4, IPV6, ARP]),
            ],
            update_allowed=False
        ),
        DSCP: properties.Schema(
            properties.Schema.STRING,
            _('DSCP bits value'),
            required=False,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Application Service')
        ),
        DIRECTION_ATTR: attributes.Schema(
            _('Direction'),
        ),
        PROTO_ATTR: attributes.Schema(
            _('Protocol used by Application Service')
        ),
        SRC_PORT_ATTR: attributes.Schema(
            _('Source port')
        ),
        DEST_PORT_ATTR: attributes.Schema(
            _('Destination port')
        ),
        DSCP_ATTR: attributes.Schema(
            _('DSCP bits value')
        ),
        TENANT_ATTR: attributes.Schema(
            _('Id of the tenant owning this Service')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def _validate_proto(self):
        proto = self.properties.get(self.PROTO)
        src = self.properties.get(self.SRC_PORT)
        dst = self.properties.get(self.DEST_PORT)
        if not src and proto in ['tcp', 'TCP', 'udp', 'UDP', '6', '17']:
            msg = _('Source port required for protocol specified')
            raise exception.StackValidationFailed(message=msg)
        if not dst and proto in ['tcp', 'TCP', 'udp', 'UDP', '6', '17']:
            msg = _('Destination port required for protocol specified')
            raise exception.StackValidationFailed(message=msg)

    def validate(self):
        super(NuageApplicationService, self).validate()
        self._validate_proto()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        service = self._get_client().create_service(
            {'service': props})['service']
        self.resource_id_set(service['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_service(self.resource_id)
        except Exception as ex:
            self.client_plugin('neutron').ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_service(self.resource_id)['service']


class NuageApplicationFlow(neutron.NeutronResource):
    """
    A resource representing Nuage Application Flow in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
        ORIGIN_TIER,
        DEST_TIER,
        SERVICE_LIST,
        SRC_ADDRESS_OVERWRITE,
        DEST_ADDRESS_OVERWRITE,
    ) = (
        'name',
        'origin_tier',
        'dest_tier',
        'nuage_services',
        'src_addr_overwrite',
        'dest_addr_overwrite',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        APP_ID_ATTR,
        ORIGIN_TIER_ATTR,
        DEST_TIER_ATTR,
        TENANT_ATTR,
        SHOW,
    ) = (
        'name',
        'application_id',
        'origin_tier',
        'dest_tier',
        'tenant_id',
        'show',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Application Flow'),
            required=True,
            update_allowed=False
        ),
        ORIGIN_TIER: properties.Schema(
            properties.Schema.STRING,
            _('ID of the originating Application Tier for the Flow'),
            constraints=[
                constraints.CustomConstraint('nuage_application.tier')
            ],
            required=True,
            update_allowed=False
        ),
        DEST_TIER: properties.Schema(
            properties.Schema.STRING,
            _('ID of the destination Application Tier for the Flow'),
            constraints=[
                constraints.CustomConstraint('nuage_application.tier')
            ],
            required=True,
            update_allowed=False
        ),
        SERVICE_LIST: properties.Schema(
            properties.Schema.LIST,
            _('List of the Application Service names associated '
              'with the Flow'),
            default=[],
            update_allowed=False
        ),
        SRC_ADDRESS_OVERWRITE: properties.Schema(
            properties.Schema.STRING,
            _('Source address overwrite value'),
            required=False,
            update_allowed=False
        ),
        DEST_ADDRESS_OVERWRITE: properties.Schema(
            properties.Schema.STRING,
            _('Destination address overwrite value'),
            required=False,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Application Flow')
        ),
        APP_ID_ATTR: attributes.Schema(
            _('ID of the Application this Flow belongs to'),
        ),
        ORIGIN_TIER_ATTR: attributes.Schema(
            _('ID of the orininating Application Tier')
        ),
        DEST_TIER_ATTR: attributes.Schema(
            _('ID of the destination Application Tier')
        ),
        TENANT_ATTR: attributes.Schema(
            _('Id of the tenant owning this Flow')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def prepare_properties(self, properties, name):
        props = dict((k, v) for k, v in properties.items()
                     if v is not None and k != self.SERVICE_LIST)

        if 'name' in properties.keys():
            props.setdefault('name', name)

        if self.SERVICE_LIST in properties.keys():
            services = properties.get(self.SERVICE_LIST)
            if len(services) > 0:
                prop = dict()
                prop['nuage_services'] = ",".join(str(i) for i in services)
                props.update(prop)

        return props

    def _validate_services(self):
        services = self.properties.get(self.SERVICE_LIST)
        src_overwrite = self.properties.get(self.SRC_ADDRESS_OVERWRITE)
        dest_overwrite = self.properties.get(self.DEST_ADDRESS_OVERWRITE)
        if src_overwrite and len(services) == 0:
            msg = _('Cannot define "src_addr_overwrite" property '
                    'without "nuage_services"')
            raise exception.StackValidationFailed(message=msg)
        if dest_overwrite and len(services) == 0:
            msg = _('Cannot define "dest_addr_overwrite" property '
                    'without "nuage_services"')
            raise exception.StackValidationFailed(message=msg)

    def validate(self):
        super(NuageApplicationFlow, self).validate()
        self._validate_services()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        flow = self._get_client().create_flow(
            {'flow': props})['flow']
        self.resource_id_set(flow['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_flow(self.resource_id)
        except Exception as ex:
            self.client_plugin('neutron').ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_flow(self.resource_id)['flow']


class NuageApplicationPort(neutron.NeutronResource):
    """
    A resource representing Nuage Application Port in Neutron.
    """

    support_status = support.SupportStatus(version='2015.1')

    PROPERTIES = (
        NAME,
        TIER,
    ) = (
        'name',
        'tier_id',
    )

    ATTRIBUTES = (
        NAME_ATTR,
        DEVICE_ID_ATTR,
        DEVICE_OWNER_ATTR,
        FIXED_IPS_ATTR,
        ADMIN_STATE_UP_ATTR,
        MAC_ADDRESS_ATTR,
        STATUS,
        NETWORK_ID_ATTR,
        SECURITY_GROUPS_ATTR,
        TENANT_ATTR,
        SHOW,
    ) = (
        'name',
        'device_id',
        'device_owner',
        'fixed_ips',
        'admin_state_up',
        'mac_address',
        'status',
        'network_id',
        'security_groups',
        'tenant_id',
        'show',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the Application Port'),
            required=True,
            update_allowed=False
        ),
        TIER: properties.Schema(
            properties.Schema.STRING,
            _('ID of the Application Tier'),
            required=True,
            update_allowed=False
        ),
    }

    attributes_schema = {
        NAME_ATTR: attributes.Schema(
            _('Name of the Application Port')
        ),
        ADMIN_STATE_UP_ATTR: attributes.Schema(
            _("The administrative state of this port.")
        ),
        DEVICE_ID_ATTR: attributes.Schema(
            _("Unique identifier for the device.")
        ),
        DEVICE_OWNER_ATTR: attributes.Schema(
            _("Name of the network owning the port.")
        ),
        FIXED_IPS_ATTR: attributes.Schema(
            _("Fixed IP addresses.")
        ),
        MAC_ADDRESS_ATTR: attributes.Schema(
            _("MAC address of the port.")
        ),
        NETWORK_ID_ATTR: attributes.Schema(
            _("Unique identifier for the network owning the port.")
        ),
        SECURITY_GROUPS_ATTR: attributes.Schema(
            _("A list of security groups for the port.")
        ),
        STATUS: attributes.Schema(
            _("The status of the port.")
        ),
        TENANT_ATTR: attributes.Schema(
            _('Id of the tenant owning this Flow')
        ),
        SHOW: attributes.Schema(
            _("All attributes.")
        ),
    }

    def _get_client(self):
        return self.neutron()

    def validate(self):
        super(NuageApplicationPort, self).validate()

    def handle_create(self):
        props = self.prepare_properties(
            self.properties,
            self.physical_resource_name())
        appdport = self._get_client().create_appdport(
            {'appdport': props})['appdport']
        self.resource_id_set(appdport['id'])

    def handle_delete(self):
        client = self._get_client()
        try:
            client.delete_appdport(self.resource_id)
        except Exception as ex:
            self.client_plugin('neutron').ignore_not_found(ex)

    def _show_resource(self):
        return self._get_client().show_appdport(self.resource_id)['appdport']


def resource_mapping():
    return {
        'Nuage::Neutron::ApplicationDomain': NuageApplicationDomain,
        'Nuage::Neutron::Application': NuageApplication,
        'Nuage::Neutron::ApplicationTier': NuageApplicationTier,
        'Nuage::Neutron::ApplicationService': NuageApplicationService,
        'Nuage::Neutron::ApplicationFlow': NuageApplicationFlow,
        'Nuage::Neutron::ApplicationPort': NuageApplicationPort,
    }


def constraint_mapping():
    return {
        'nuage_application.applicationdomain': ApplicationDomainConstraint,
        'nuage_application.application': ApplicationConstraint,
        'nuage_application.tier': ApplicationTierConstraint,
    }

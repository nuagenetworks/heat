# Copyright 2018 NOKIA
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

from heat.common.i18n import _
from heat.engine import properties
from heat.engine.resources.openstack.neutron.security_group import \
    SecurityGroup


class NuageSecurityGroup(SecurityGroup):

    VALUE_SPECS = 'value_specs'
    SecurityGroup.PROPERTIES += (VALUE_SPECS,)

    SecurityGroup.properties_schema[VALUE_SPECS] = properties.Schema(
            properties.Schema.MAP,
            _('Extra parameters to include in the creation request.'),
            default={},
            update_allowed=True
        )


def resource_mapping():
    return {
        'Nuage::Neutron::SecurityGroup': NuageSecurityGroup,
    }

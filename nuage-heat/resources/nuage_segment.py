# Copyright 2020 NOKIA
# All Rights Reserved.
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
from heat.engine import constraints
from heat.engine import properties

from heat.engine.resources.openstack.neutron.segment import Segment


class NuageSegment(Segment):
    """A resource for Nuage segments

    It adds nuage_hybrid_mpls to the list of supported network types.

    This requires enabling the segments service plug-in by appending
    'segments' to the list of service_plugins in the neutron.conf.
    """

    Segment.NETWORK_TYPES += ('nuage_hybrid_mpls',)

    Segment.properties_schema[Segment.NETWORK_TYPE] = properties.Schema(
        properties.Schema.STRING,
        _('Type of network to associate with this segment.'),
        constraints=[
            constraints.AllowedValues(Segment.NETWORK_TYPES),
        ],
        required=True
    )


def resource_mapping():
    return {
        'Nuage::Neutron::NuageSegment': NuageSegment
    }

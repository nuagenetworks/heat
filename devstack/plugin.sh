#!/bin/bash

# Copyright 2015 Alcatel-Lucent USA Inc.
#
# All Rights Reserved
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


# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace



dir=${GITDIR['nuage-openstack-heat']}/devstack


if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing Heat Nuage plugin"
    setup_develop ${GITDIR['nuage-openstack-heat']}
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring Heat Nuage plugin"
    iniset $HEAT_CONF DEFAULT plugin_dirs ${GITDIR['nuage-openstack-heat']}
fi

if [[ "$1" == "unstack" ]]; then
        # no-op
        :
fi

# Restore xtrace
$XTRACE


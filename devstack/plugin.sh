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
elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        if is_service_enabled tempest; then
            echo_summary "Configuring Tempest for Heat"
            source $TOP_DIR/openrc demo demo

            iniset $TEMPEST_CONFIG heat_plugin username $OS_USERNAME
            iniset $TEMPEST_CONFIG heat_plugin password $OS_PASSWORD
            iniset $TEMPEST_CONFIG heat_plugin project_name $OS_PROJECT_NAME
            iniset $TEMPEST_CONFIG heat_plugin auth_url $OS_AUTH_URL
            iniset $TEMPEST_CONFIG heat_plugin user_domain_id $OS_USER_DOMAIN_ID
            iniset $TEMPEST_CONFIG heat_plugin project_domain_id $OS_PROJECT_DOMAIN_ID
            iniset $TEMPEST_CONFIG heat_plugin user_domain_name $OS_USER_DOMAIN_NAME
            iniset $TEMPEST_CONFIG heat_plugin project_domain_name $OS_PROJECT_DOMAIN_NAME
            iniset $TEMPEST_CONFIG heat_plugin region $OS_REGION_NAME
            iniset $TEMPEST_CONFIG heat_plugin auth_version $OS_IDENTITY_API_VERSION

            source $TOP_DIR/openrc admin admin
            iniset $TEMPEST_CONFIG heat_plugin admin_username $OS_USERNAME
            iniset $TEMPEST_CONFIG heat_plugin admin_password $OS_PASSWORD

            if is_service_enabled tls-proxy; then
                iniset $TEMPEST_CONFIG heat_plugin ca_file $SSL_BUNDLE_FILE
            fi
        fi
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


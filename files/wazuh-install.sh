#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

adminpem="/etc/wazuh-indexer/certs/admin.pem"
adminkey="/etc/wazuh-indexer/certs/admin-key.pem"
readonly wazuh_major="4.12"
readonly wazuh_version="4.12.0"
readonly filebeat_version="7.10.2-*"
readonly wazuh_install_vesion="0.1"
source_branch="v${wazuh_version}"
last_stage="rc1"
repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/4.x"
reporelease="stable"
filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.4.tar.gz"
bucket="packages.wazuh.com"
repository="4.x"
readonly resources="https://${bucket}/${wazuh_major}"
readonly base_url="https://${bucket}/${repository}"
base_path="$(dirname "$(readlink -f "$0")")"
readonly base_path
config_file="${base_path}/config.yml"
readonly tar_file_name="wazuh-install-files.tar"
tar_file="${base_path}/${tar_file_name}"
filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/extensions/elasticsearch/7.x/wazuh-template.json"
readonly dashboard_cert_path="/etc/wazuh-dashboard/certs"
readonly filebeat_cert_path="/etc/filebeat/certs"
readonly indexer_cert_path="/etc/wazuh-indexer/certs"
readonly logfile="/var/log/wazuh-install.log"
debug=">> ${logfile} 2>&1"
readonly yum_lockfile="/var/run/yum.pid"
readonly apt_lockfile="/var/lib/dpkg/lock"
readonly base_dest_folder="wazuh-offline"
manager_deb_base_url="${base_url}/apt/pool/main/w/wazuh-manager"
filebeat_deb_base_url="${base_url}/apt/pool/main/f/filebeat"
indexer_deb_base_url="${base_url}/apt/pool/main/w/wazuh-indexer"
dashboard_deb_base_url="${base_url}/apt/pool/main/w/wazuh-dashboard"
manager_rpm_base_url="${base_url}/yum"
filebeat_rpm_base_url="${base_url}/yum"
indexer_rpm_base_url="${base_url}/yum"
dashboard_rpm_base_url="${base_url}/yum"
readonly wazuh_gpg_key="https://${bucket}/key/GPG-KEY-WAZUH"
filebeat_config_file="${resources}/tpl/wazuh/filebeat/filebeat.yml"
readonly offline_filebeat_version="7.10.2"
adminUser="wazuh"
adminPassword="wazuh"
http_port=443
wazuh_aio_ports=( 9200 9300 1514 1515 1516 55000 "${http_port}")
readonly wazuh_indexer_ports=( 9200 9300 )
readonly wazuh_manager_ports=( 1514 1515 1516 55000 )
wazuh_dashboard_port="${http_port}"
wia_yum_dependencies=( systemd grep tar coreutils sed procps-ng gawk curl )
readonly wia_apt_dependencies=( systemd grep tar coreutils sed procps gawk curl )
readonly wazuh_yum_dependencies=( libcap )
readonly wazuh_apt_dependencies=( apt-transport-https libcap2-bin software-properties-common gnupg )
readonly indexer_yum_dependencies=( coreutils )
readonly indexer_apt_dependencies=( debconf adduser procps gnupg apt-transport-https )
readonly dashboard_yum_dependencies=( libcap )
readonly dashboard_apt_dependencies=( debhelper tar curl libcap2-bin gnupg apt-transport-https )
readonly wia_offline_dependencies=( curl tar gnupg openssl lsof )
wia_dependencies_installed=()

config_file_dashboard_dashboard_assistant="server.host: 0.0.0.0
opensearch.hosts: https://127.0.0.1:9200
server.port: 443
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/dashboard-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/dashboard.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: true"

config_file_dashboard_dashboard="server.host: \"<kibana-ip>\"
opensearch.hosts: https://<elasticsearch-ip>:9200
server.port: 443
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/kibana-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/kibana.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
server.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: true"

config_file_dashboard_dashboard_all_in_one="server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://localhost:9200
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/kibana-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/kibana.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: true"

config_file_dashboard_dashboard_assistant_distributed="server.port: 443
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/dashboard-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/dashboard.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: true"

config_file_certificate_config="nodes:
  # Wazuh indexer nodes
  indexer:
    - name: indexer-1
      ip: \"<indexer-node-ip>\"
    - name: indexer-2
      ip: \"<indexer-node-ip>\"
    - name: indexer-3
      ip: \"<indexer-node-ip>\"
  server:
    - name: server-1
      ip: \"<server-node-ip>\"
      node_type: master
    - name: server-2
      ip: \"<server-node-ip>\"
      node_type: worker
    - name: server-3
      ip: \"<server-node-ip>\"
      node_type: worker
  dashboard:
    - name: dashboard-1
      ip: \"<dashboard-node-ip>\"
    - name: dashboard-2
      ip: \"<dashboard-node-ip>\"
    - name: dashboard-3
      ip: \"<dashboard-node-ip>\""

config_file_certificate_config_aio="nodes:
  indexer:
    - name: wazuh-indexer
      ip: 127.0.0.1
  server:
    - name: wazuh-server
      ip: 127.0.0.1
  dashboard:
    - name: wazuh-dashboard
      ip: 127.0.0.1"

config_file_indexer_indexer_all_in_one="network.host: \"127.0.0.1\"
node.name: \"node-1\"
cluster.initial_master_nodes:
- \"node-1\"
cluster.name: \"wazuh-cluster\"

node.max_local_storage_nodes: \"3\"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled_ciphers:
  - \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\"
plugins.security.ssl.http.enabled_protocols:
  - \"TLSv1.2\"
plugins.security.authcz.admin_dn:
- \"CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US\"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- \"CN=indexer,OU=Wazuh,O=Wazuh,L=California,C=US\"
plugins.security.restapi.roles_enabled:
- \"all_access\"
- \"security_rest_api_access\"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [\".opendistro-alerting-config\", \".opendistro-alerting-alert*\", \".opendistro-anomaly-results*\", \".opendistro-anomaly-detector*\", \".opendistro-anomaly-checkpoints\", \".opendistro-anomaly-detection-state\", \".opendistro-reports-*\", \".opendistro-notifications-*\", \".opendistro-notebooks\", \".opensearch-observability\", \".opendistro-asynchronous-search-response*\", \".replication-metadata-store\"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true"

config_file_indexer_roles_roles="_meta:
  type: \"roles\"
  config_version: 2

# Restrict users so they can only view visualization and dashboard on kibana
kibana_read_only:
  reserved: true

# The security REST API access role is used to assign specific users access to change the security settings through the REST API.
security_rest_api_access:
  reserved: true

# Allows users to view monitors, destinations and alerts
alerting_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/get'
    - 'cluster:admin/opendistro/alerting/destination/get'
    - 'cluster:admin/opendistro/alerting/monitor/get'
    - 'cluster:admin/opendistro/alerting/monitor/search'

# Allows users to view and acknowledge alerts
alerting_ack_alerts:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/*'

# Allows users to use all alerting functionality
alerting_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/alerting/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allow users to read Anomaly Detection detectors and results
anomaly_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/ad/detector/info'
    - 'cluster:admin/opendistro/ad/detector/search'
    - 'cluster:admin/opendistro/ad/detectors/get'
    - 'cluster:admin/opendistro/ad/result/search'
    - 'cluster:admin/opendistro/ad/tasks/search'

# Allows users to use all Anomaly Detection functionality
anomaly_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/ad/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allows users to read Notebooks
notebooks_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/list'
    - 'cluster:admin/opendistro/notebooks/get'

# Allows users to all Notebooks functionality
notebooks_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/create'
    - 'cluster:admin/opendistro/notebooks/update'
    - 'cluster:admin/opendistro/notebooks/delete'
    - 'cluster:admin/opendistro/notebooks/get'
    - 'cluster:admin/opendistro/notebooks/list'

# Allows users to read and download Reports
reports_instances_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to read and download Reports and Report-definitions
reports_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to all Reports functionality
reports_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/create'
    - 'cluster:admin/opendistro/reports/definition/update'
    - 'cluster:admin/opendistro/reports/definition/on_demand'
    - 'cluster:admin/opendistro/reports/definition/delete'
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to use all asynchronous-search functionality
asynchronous_search_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:data/read/search*'

# Allows users to read stored asynchronous-search results
asynchronous_search_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/get'

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - \"wazuh-*\"
    dls: \"\"
    fls: []
    masked_fields: []
    allowed_actions:
    - \"read\"
    - \"delete\"
    - \"manage\"
    - \"index\"
  tenant_permissions: []
  static: false"

config_file_indexer_roles_roles_mapping="---
# In this file users, backendroles and hosts can be mapped to Open Distro Security roles.
# Permissions for Opendistro roles are configured in roles.yml

_meta:
  type: \"rolesmapping\"
  config_version: 2

# Define your roles mapping here

## Default roles mapping

all_access:
  reserved: true
  hidden: false
  backend_roles:
  - \"admin\"
  hosts: []
  users: []
  and_backend_roles: []
  description: \"Maps admin to all_access\"

own_index:
  reserved: false
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - \"*\"
  and_backend_roles: []
  description: \"Allow full access to an index named like the username\"

logstash:
  reserved: false
  hidden: false
  backend_roles:
  - \"logstash\"
  hosts: []
  users: []
  and_backend_roles: []

readall:
  reserved: true
  hidden: false
  backend_roles:
  - \"readall\"
  hosts: []
  users: []
  and_backend_roles: []

manage_snapshots:
  reserved: true
  hidden: false
  backend_roles:
  - \"snapshotrestore\"
  hosts: []
  users: []
  and_backend_roles: []

kibana_server:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - \"kibanaserver\"
  and_backend_roles: []

kibana_user:
  reserved: false
  hidden: false
  backend_roles:
  - \"kibanauser\"
  hosts: []
  users: []
  and_backend_roles: []
  description: \"Maps kibanauser to kibana_user\"

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - \"kibanaserver\"
  and_backend_roles: []"

config_file_indexer_roles_internal_users="---
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: \"internalusers\"
  config_version: 2

# Define your internal users here

## Demo users

admin:
  hash: \"\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG\"
  reserved: true
  backend_roles:
  - \"admin\"
  description: \"Demo admin user\"

kibanaserver:
  hash: \"\$2a\$12\$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.\"
  reserved: true
  description: \"Demo kibanaserver user\"

kibanaro:
  hash: \"\$2a\$12\$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC\"
  reserved: false
  backend_roles:
  - \"kibanauser\"
  - \"readall\"
  attributes:
    attribute1: \"value1\"
    attribute2: \"value2\"
    attribute3: \"value3\"
  description: \"Demo kibanaro user\"

logstash:
  hash: \"\$2a\$12\$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2\"
  reserved: false
  backend_roles:
  - \"logstash\"
  description: \"Demo logstash user\"

readall:
  hash: \"\$2a\$12\$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2\"
  reserved: false
  backend_roles:
  - \"readall\"
  description: \"Demo readall user\"

snapshotrestore:
  hash: \"\$2y\$12\$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W\"
  reserved: false
  backend_roles:
  - \"snapshotrestore\"
  description: \"Demo snapshotrestore user\""

config_file_indexer_indexer="network.host: 0.0.0.0
node.name: node-1
cluster.initial_master_nodes: node-1

plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled_ciphers:
  - \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\"
plugins.security.ssl.http.enabled_protocols:
  - \"TLSv1.2\"
plugins.security.nodes_dn:
- CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US
plugins.security.authcz.admin_dn:
- CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US

plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: [\"all_access\", \"security_rest_api_access\"]
cluster.routing.allocation.disk.threshold_enabled: false
node.max_local_storage_nodes: 3

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true"

config_file_indexer_indexer_assistant_distributed="node.master: true
node.data: true
node.ingest: true

cluster.name: wazuh-indexer-cluster
cluster.routing.allocation.disk.threshold_enabled: false

node.max_local_storage_nodes: \"3\"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer


plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled_ciphers:
  - \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\"
plugins.security.ssl.http.enabled_protocols:
  - \"TLSv1.2\"
plugins.security.authcz.admin_dn:
- \"CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US\"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.restapi.roles_enabled:
- \"all_access\"
- \"security_rest_api_access\"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [\".opendistro-alerting-config\", \".opendistro-alerting-alert*\", \".opendistro-anomaly-results*\", \".opendistro-anomaly-detector*\", \".opendistro-anomaly-checkpoints\", \".opendistro-anomaly-detection-state\", \".opendistro-reports-*\", \".opendistro-notifications-*\", \".opendistro-notebooks\", \".opensearch-observability\", \".opendistro-asynchronous-search-response*\", \".replication-metadata-store\"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true"

config_file_filebeat_filebeat_elastic_cluster="# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: [\"<elasticsearch_ip_node_1>:9200\", \"<elasticsearch_ip_node_2>:9200\", \"<elasticsearch_ip_node_3>:9200\"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat="# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: [\"<elasticsearch_ip>:9200\"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_all_in_one="# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: [\"127.0.0.1:9200\"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_distributed="# Wazuh - Filebeat configuration file
output.elasticsearch:
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_assistant="# Wazuh - Filebeat configuration file
output.elasticsearch.hosts:
        - 127.0.0.1:9200
#        - <elasticsearch_ip_node_2>:9200
#        - <elasticsearch_ip_node_3>:9200

output.elasticsearch:
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

trap installCommon_cleanExit SIGINT
export JAVA_HOME="/usr/share/wazuh-indexer/jdk/"
# ------------ checks.sh ------------ 
function checks_arch() {

    common_logger -d "Checking system architecture."
    architecture=$(uname -m)

    if [ "${architecture}" == "x86_64" ] || [ "${architecture}" == "aarch64" ]; then
        common_logger -d "System architecture: ${architecture}"
    else
        common_logger -e "Uncompatible system architecture: ${architecture}. Supported any 64-bit system"
        exit 1
    fi
}
function checks_arguments() {

    # -------------- Repository selection ---------------------

    if [ -n "${development}" ]; then
        if [ -z "${AIO}" ] && [ -z "${dashboard}" ] && [ -z "${indexer}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ] && [ -z "${download}" ]; then
            common_logger -e "The -d|--development option must be used with -a, -ws, -s, -wi, -wd or -dw."
            exit 1
        fi
    fi

    # -------------- Port option validation ---------------------

    if [ -n "${port_specified}" ]; then
        if [ -z "${AIO}" ] && [ -z "${dashboard}" ]; then
            common_logger -e "The argument -p|--port can only be used with -a|--all-in-one or -wd|--wazuh-dashboard."
            exit 1
        fi
    fi

    # -------------- Offline installation ---------------------

    if [ -n "${offline_install}" ]; then
        if [ -z "${AIO}" ] && [ -z "${dashboard}" ] && [ -z "${indexer}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
            common_logger -e "The -of|--offline-installation option must be used with -a, -ws, -s, -wi, or -wd."
            exit 1
        fi
    fi

    if [ -n "${download}" ] && [ -z "${download_arch}" ]; then
        common_logger -e "To download the packages it is necessary to set the architecture in -da|--download-arch <amd64|x86_64|arm64|aarch64>"
        exit 1
    fi

    if [ -n "${download}" ] && [ -n "${download_arch}" ]; then
        if [ "${package_type}" = "deb" ]; then
            if [ "${arch}" != "amd64" ] && [ "${arch}" != "arm64" ]; then
                if [ "${arch}" = "x86_64" ]; then
                    common_logger -e "Architecture ${arch} not valid for package type ${package_type}. Use amd64 instead."
                elif [ "${arch}" = "aarch64" ]; then
                    common_logger -e "Architecture ${arch} not valid for package type ${package_type}. Use arm64 instead."
                else
                    common_logger -e "Architecture ${arch} not valid for package type ${package_type}"
                fi
                exit 1
            fi
        elif [ "${package_type}" = "rpm" ]; then
            if [ "${arch}" != "x86_64" ] && [ "${arch}" != "aarch64" ]; then
                if [ "${arch}" = "amd64" ]; then
                    common_logger -e "Architecture ${arch} not valid for package type ${package_type}. Use x86_64 instead."
                elif [ "${arch}" = "arm64" ]; then
                    common_logger -e "Architecture ${arch} not valid for package type ${package_type}. Use aarch64 instead."
                else
                    common_logger -e "Architecture ${arch} not valid for package type ${package_type}"
                fi
                exit 1
            fi
        fi
    fi

    # -------------- Configurations ---------------------------------

    if [ -f "${tar_file}" ]; then
        if [ -n "${AIO}" ]; then
            rm -f "${tar_file}"
        fi
        if [ -n "${configurations}" ]; then
            common_logger -e "File ${tar_file} already exists. Please remove it if you want to use a new configuration."
            exit 1
        fi
    fi

    if [[ -n "${configurations}" && ( -n "${AIO}" || -n "${indexer}" || -n "${dashboard}" || -n "${wazuh}" || -n "${overwrite}" || -n "${start_indexer_cluster}" || -n "${tar_conf}" || -n "${uninstall}" ) ]]; then
        common_logger -e "The argument -g|--generate-config-files can't be used with -a|--all-in-one, -o|--overwrite, -s|--start-cluster, -t|--tar, -u|--uninstall, -wd|--wazuh-dashboard, -wi|--wazuh-indexer, or -ws|--wazuh-server."
        exit 1
    fi

    # -------------- Overwrite --------------------------------------

    if [ -n "${overwrite}" ] && [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ]; then
        common_logger -e "The argument -o|--overwrite must be used in conjunction with -a|--all-in-one, -wd|--wazuh-dashboard, -wi|--wazuh-indexer, or -ws|--wazuh-server."
        exit 1
    fi

    # -------------- Uninstall --------------------------------------

    if [ -n "${uninstall}" ]; then

        if [ -n "$AIO" ] || [ -n "$indexer" ] || [ -n "$dashboard" ] || [ -n "$wazuh" ]; then
            common_logger -e "It is not possible to uninstall and install in the same operation. If you want to overwrite the components use -o|--overwrite."
            exit 1
        fi

        if [ -z "${wazuh_installed}" ] && [ -z "${wazuh_remaining_files}" ]; then
            common_logger "Wazuh manager not found in the system so it was not uninstalled."
        fi

        if [ -z "${filebeat_installed}" ] && [ -z "${filebeat_remaining_files}" ]; then
            common_logger "Filebeat not found in the system so it was not uninstalled."
        fi

        if [ -z "${indexer_installed}" ] && [ -z "${indexer_remaining_files}" ]; then
            common_logger "Wazuh indexer not found in the system so it was not uninstalled."
        fi

        if [ -z "${dashboard_installed}" ] && [ -z "${dashboard_remaining_files}" ]; then
            common_logger "Wazuh dashboard not found in the system so it was not uninstalled."
        fi

    fi

    # -------------- All-In-One -------------------------------------

    if [ -n "${AIO}" ]; then

        if [ -n "$indexer" ] || [ -n "$dashboard" ] || [ -n "$wazuh" ]; then
            common_logger -e "Argument -a|--all-in-one is not compatible with -wi|--wazuh-indexer, -wd|--wazuh-dashboard or -ws|--wazuh-server."
            exit 1
        fi

        if [ -n "${overwrite}" ]; then
            installCommon_rollBack
        fi

        if  [ -z "${overwrite}" ] && { [ -n "${wazuh_installed}" ] || [ -n "${wazuh_remaining_files}" ]; }; then
            common_logger -e "Wazuh manager already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && { [ -n "${indexer_installed}" ] || [ -n "${indexer_remaining_files}" ]; };then
            common_logger -e "Wazuh indexer already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && { [ -n "${dashboard_installed}" ] || [ -n "${dashboard_remaining_files}" ]; }; then
            common_logger -e "Wazuh dashboard already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && { [ -n "${filebeat_installed}" ] || [ -n "${filebeat_remaining_files}" ]; }; then
            common_logger -e "Filebeat already installed."
            installedComponent=1
        fi
        if [ -n "${installedComponent}" ]; then
            common_logger "If you want to overwrite the current installation, run this script adding the option -o/--overwrite. This will erase all the existing configuration and data."
            exit 1
        fi

    fi

    # -------------- Indexer ----------------------------------

    if [ -n "${indexer}" ]; then

        if [ -n "${indexer_installed}" ] || [ -n "${indexer_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh indexer is already installed in this node or some of its files have not been removed. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh dashboard --------------------------------

    if [ -n "${dashboard}" ]; then
        if [ -n "${dashboard_installed}" ] || [ -n "${dashboard_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh dashboard is already installed in this node or some of its files have not been removed. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh ------------------------------------------

    if [ -n "${wazuh}" ]; then
        if [ -n "${wazuh_installed}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${filebeat_installed}" ] || [ -n "${filebeat_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh server components (wazuh-manager and filebeat) are already installed in this node or some of their files have not been removed. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Cluster start ----------------------------------

    if [[ -n "${start_indexer_cluster}" && ( -n "${AIO}" || -n "${indexer}" || -n "${dashboard}" || -n "${wazuh}" || -n "${overwrite}" || -n "${configurations}" || -n "${tar_conf}" || -n "${uninstall}") ]]; then
        common_logger -e "The argument -s|--start-cluster can't be used with -a|--all-in-one, -g|--generate-config-files,-o|--overwrite , -u|--uninstall, -wi|--wazuh-indexer, -wd|--wazuh-dashboard, -s|--start-cluster, -ws|--wazuh-server."
        exit 1
    fi

    # -------------- Global -----------------------------------------

    if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ] && [ -z "${configurations}" ] && [ -z "${uninstall}" ] && [ -z "${download}" ]; then
        common_logger -e "At least one of these arguments is necessary -a|--all-in-one, -g|--generate-config-files, -wi|--wazuh-indexer, -wd|--wazuh-dashboard, -s|--start-cluster, -ws|--wazuh-server, -u|--uninstall, -dw|--download-wazuh."
        exit 1
    fi

    if [ -n "${force}" ] && [ -z  "${dashboard}" ]; then
        common_logger -e "The -fd|--force-install-dashboard argument needs to be used alongside -wd|--wazuh-dashboard."
        exit 1
    fi

}
function check_curlVersion() {

    common_logger -d "Checking curl tool version."
    # --retry-connrefused was added in 7.52.0
    curl_version=$(curl -V | head -n 1 | awk '{ print $2 }')
    if [ $(check_versions ${curl_version} 7.52.0) == "0" ]; then
        curl_has_connrefused=0
    fi

}
function check_dist() {
    common_logger -d "Checking system distribution."
    dist_detect
    if  [ "${DIST_NAME}" != "centos" ] && [ "${DIST_NAME}" != "rhel" ] &&
        [ "${DIST_NAME}" != "amzn" ]   && [ "${DIST_NAME}" != "ubuntu" ] && [ "${DIST_NAME}" != "rocky" ]; then
        notsupported=1
    fi
    if [ "${DIST_NAME}" == "centos" ] && { [ "${DIST_VER}" -ne "7" ] && [ "${DIST_VER}" -ne "8" ]; }; then
        notsupported=1
    fi
    if [ "${DIST_NAME}" == "rhel" ] && { [ "${DIST_VER}" -ne "7" ] && [ "${DIST_VER}" -ne "8" ] && [ "${DIST_VER}" -ne "9" ]; }; then
        notsupported=1
    fi

    if [ "${DIST_NAME}" == "amzn" ]; then
        if  [ "${DIST_VER}" != "2" ] &&
            [ "${DIST_VER}" != "2023" ] &&
            [ "${DIST_VER}" != "2018.03" ]; then
            notsupported=1
        fi
        if [ "${DIST_VER}" -eq "2023" ]; then
            checks_specialDepsAL2023
        fi
    fi

    if [ "${DIST_NAME}" == "ubuntu" ]; then
        if  [ "${DIST_VER}" == "16" ] || [ "${DIST_VER}" == "18" ] ||
            [ "${DIST_VER}" == "20" ] || [ "${DIST_VER}" == "22" ] ||
            [ "${DIST_VER}" == "24" ]; then
            if [ "${DIST_SUBVER}" != "04" ]; then
                notsupported=1
            fi
        else
            notsupported=1
        fi
    fi

    if [ "${DIST_NAME}" == "rocky" ]; then
        if [ "${DIST_VER}" != "9" ] || [ "${DIST_SUBVER}" != "4" ]; then
            notsupported=1
        fi
    fi

    if [ -n "${notsupported}" ]; then
        common_logger "The recommended systems are: Red Hat Enterprise Linux 7, 8, 9; CentOS 7, 8; Amazon Linux 2; Ubuntu 16.04, 18.04, 20.04, 22.04."
        common_logger -w "The current system does not match with the list of recommended systems. The installation may not work properly."
    fi
    common_logger -d "Detected distribution name: ${DIST_NAME}"
    common_logger -d "Detected distribution version: ${DIST_VER}"

}
function checks_health() {

    checks_specifications

    common_logger -d "CPU cores detected: ${cores}"
    common_logger -d "Free RAM memory detected: ${ram_gb}"

    if [ -n "${indexer}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

    if [ -n "${dashboard}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

    if [ -n "${wazuh}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 1700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores . If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

    if [ -n "${AIO}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

}
function checks_names() {

    common_logger -d "Checking node names in the configuration file."
    if [ -n "${indxname}" ] && [ -n "${dashname}" ] && [ "${indxname}" == "${dashname}" ]; then
        common_logger -e "The node names for Wazuh indexer and Wazuh dashboard must be different."
        exit 1
    fi

    if [ -n "${indxname}" ] && [ -n "${winame}" ] && [ "${indxname}" == "${winame}" ]; then
        common_logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -n "${dashname}" ] && [ "${winame}" == "${dashname}" ]; then
        common_logger -e "The node names for Wazuh server and Wazuh indexer must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && ! echo "${server_node_names[@]}" | grep -w -q "${winame}"; then
        common_logger -e "The Wazuh server node name ${winame} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${indxname}" ] && ! echo "${indexer_node_names[@]}" | grep -w -q "${indxname}"; then
        common_logger -e "The Wazuh indexer node name ${indxname} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${dashname}" ] && ! echo "${dashboard_node_names[@]}" | grep -w -q "${dashname}"; then
        common_logger -e "The Wazuh dashboard node name ${dashname} does not appear on the configuration file."
        exit 1
    fi

    if [[ "${dashname}" == -* ]] || [[ "${indxname}" == -* ]] || [[ "${winame}" == -* ]]; then
        common_logger -e "Node name cannot start with \"-\""
        exit 1
    fi

}
function checks_previousCertificate() {
    common_logger -d "Checking previous certificate existence."
    if [ ! -f "${tar_file}" ]; then
        common_logger -e "Cannot find ${tar_file}. Run the script with the option -g|--generate-config-files to create it or copy it from another node."
        exit 1
    fi

    if [ -n "${indxname}" ]; then
        if ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${indxname}".pem  || ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${indxname}"-key.pem; then
            common_logger -e "There is no certificate for the indexer node ${indxname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${dashname}" ]; then
        if ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${dashname}".pem || ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${dashname}"-key.pem; then
            common_logger -e "There is no certificate for the Wazuh dashboard node ${dashname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${winame}" ]; then
        if ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${winame}".pem || ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${winame}"-key.pem; then
            common_logger -e "There is no certificate for the wazuh server node ${winame} in ${tar_file}."
            exit 1
        fi
    fi
}
function checks_specialDepsAL2023() {

    # Change curl for curl-minimal
    wia_yum_dependencies=( "${wia_yum_dependencies[@]/curl/curl-minimal}" )

    # In containers, coreutils is replaced for coreutils-single
    if [ -f "/.dockerenv" ]; then
        wia_yum_dependencies=( "${wia_yum_dependencies[@]/coreutils/coreutils-single}" )
    fi
}
function checks_specifications() {

    cores=$(grep -c processor /proc/cpuinfo)
    ram_gb=$(free -m | awk 'FNR == 2 {print $2}')

}
function checks_ports() {

    if [ -z "${offline_install}" ]; then
        dep="lsof"
        if [ "${sys_type}" == "yum" ]; then
            installCommon_yumInstallList "${dep}"
        elif [ "${sys_type}" == "apt-get" ]; then
            installCommon_aptInstallList "${dep}"
        fi

        if [ "${#not_installed[@]}" -gt 0 ]; then
                wia_dependencies_installed+=("${dep}")
        fi
    fi

    common_logger -d "Checking ports availability."
    used_port=0
    ports=("$@")

    checks_firewall "${ports[@]}"

    if command -v lsof > /dev/null; then
        port_command="lsof -sTCP:LISTEN  -i:"
    else
        common_logger -w "Cannot find lsof. Port checking will be skipped."
        return 1
    fi

    for i in "${!ports[@]}"; do
        if eval "${port_command}""${ports[i]}" > /dev/null; then
            used_port=1
            common_logger -e "Port ${ports[i]} is being used by another process. Please, check it before installing Wazuh."
        fi
    done

    if [ "${used_port}" -eq 1 ]; then
        common_logger "The installation can not continue due to port usage by other processes."
        installCommon_rollBack
        exit 1
    fi

}
function check_versions() {

    if test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"; then
        echo 0
    else
        echo 1
    fi
}
function checks_available_port() {
    chosen_port="$1"
    shift
    ports_list=("$@")

    if [ "$chosen_port" -ne "${http_port}" ]; then
        for port in "${ports_list[@]}"; do
            if [ "$chosen_port" -eq "$port" ]; then
                common_logger -e "Port ${chosen_port} is reserved by Wazuh. Please, choose another port."
                exit 1
            fi
        done
    fi
}
function checks_filebeatURL() {
    # URL uses branch when the source_branch is not a stage branch
    if [[ ! $last_stage ]]; then
        source_branch="${source_branch#v}"
        filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/extensions/elasticsearch/7.x/wazuh-template.json"
    fi

    # URL using master branch
    new_filebeat_url="${filebeat_wazuh_template/${source_branch}/main}"

    response=$(curl -I --write-out '%{http_code}' --silent --output /dev/null $filebeat_wazuh_template)
    if [ "${response}" != "200" ]; then
        response=$(curl -I --write-out '%{http_code}' --silent --output /dev/null $new_filebeat_url)

        # Display error if both URLs do not get the resource
        if [ "${response}" != "200" ]; then
            common_logger -e "Could not get the Filebeat Wazuh template."
        else
            common_logger "Using Filebeat template from master branch."
            filebeat_wazuh_template="${new_filebeat_url}"
        fi
    fi
}
function checks_development_source_tag() {
    source_branch="${source_branch}-${last_stage}"

    # Check if the stage tag exists
    status_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://api.github.com/repos/wazuh/wazuh-installation-assistant/git/refs/tags/$source_branch")

    if [ "$status_code" -ne 200 ]; then
        common_logger -w "Tag '$source_branch' does not exist. Using the source branch related to the Wazuh version ($wazuh_version)."
        source_branch="${wazuh_version}"

        # Check if the source branch exists
        checks_source_branch
    fi
}
function checks_source_branch() {
    # Check if the source branch exists
    status_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://api.github.com/repos/wazuh/wazuh-installation-assistant/branches/$source_branch")

    if [ "$status_code" -ne 200 ]; then
        common_logger -w "Branch '$source_branch' does not exist. Using the main branch."
        source_branch="main"
    fi
}
function checks_firewall(){
    ports_list=("$@")
    f_ports=""
    f_message="The system has firewall enabled. Please ensure that traffic is allowed on "
    firewalld_installed=0
    ufw_installed=0


    # Record of the ports that must be exposed according to the installation
    if [ -n "${AIO}" ]; then
        f_message+="these ports: 1515, 1514, ${http_port}"
    elif [ -n "${dashboard}" ]; then
        f_message+="this port: ${http_port}"
    else
        f_message+="these ports:"
        for port in "${ports_list[@]}"; do
            f_message+=" ${port},"
        done

        # Deletes last comma
        f_message="${f_message%,}"
    fi

    # Check if the firewall is installed
    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q firewalld --quiet && firewalld_installed=1"
        eval "rpm -q ufw --quiet && ufw_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        if apt list --installed 2>/dev/null | grep -q -E ^"firewalld"\/; then
            firewalld_installed=1
        fi
        if apt list --installed 2>/dev/null | grep -q -E ^"ufw"\/; then
            ufw_installed=1
        fi
    fi

    # Check if the firewall is running
    if [ "${firewalld_installed}" == "1" ]; then
        if firewall-cmd --state 2>/dev/null | grep -q -w "running"; then
            common_logger -w "${f_message/firewall/Firewalld}."
        fi
    fi
    if [ "${ufw_installed}" == "1" ]; then
        if ufw status 2>/dev/null | grep -q -w "active"; then
            common_logger -w "${f_message/firewall/UFW}."
        fi
    fi

}

# ------------ installMain.sh ------------ 
function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Install and configure Wazuh central components: Wazuh server, Wazuh indexer, and Wazuh dashboard."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [OPTIONS] -a | -c | -s | -wi <indexer-node-name> | -wd <dashboard-node-name> | -ws <server-node-name>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --all-in-one"
    echo -e "                Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard."
    echo -e ""
    echo -e "        -c,  --config-file <path-to-config-yml>"
    echo -e "                Path to the configuration file used to generate wazuh-install-files.tar file containing the files that will be needed for installation. By default, the Wazuh installation assistant will search for a file named config.yml in the same path as the script."
    echo -e ""
    echo -e "        -d [pre-release|staging],  --development"
    echo -e "                Use development repositories. By default it uses the pre-release package repository. If staging is specified, it will use that repository."
    echo -e ""
    echo -e "        -dw,  --download-wazuh <deb|rpm>"
    echo -e "                Download all the packages necessary for offline installation. Type of packages to download for offline installation (rpm, deb)"
    echo -e ""
    echo -e "        -da,  --download-arch <amd64|arm64|x86_64|aarch64>"
    echo -e "                Define the architecture of the packages to download for offline installation."
    echo -e ""
    echo -e "        -fd,  --force-install-dashboard"
    echo -e "                Force Wazuh dashboard installation to continue even when it is not capable of connecting to the Wazuh indexer."
    echo -e ""
    echo -e "        -g,  --generate-config-files"
    echo -e "                Generate wazuh-install-files.tar file containing the files that will be needed for installation from config.yml. In distributed deployments you will need to copy this file to all hosts."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Display this help and exit."
    echo -e ""
    echo -e "        -i,  --ignore-check"
    echo -e "                Ignore the check for minimum hardware requirements."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrites previously installed components. This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -of,  --offline-installation"
    echo -e "                Perform an offline installation. This option must be used with -a, -ws, -s, -wi, or -wd."
    echo -e ""
    echo -e "        -p,  --port"
    echo -e "                Specifies the Wazuh web user interface port. By default is the 443 TCP port. Recommended ports are: 8443, 8444, 8080, 8888, 9000."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Initialize Wazuh indexer cluster security settings."
    echo -e ""
    echo -e "        -t,  --tar <path-to-certs-tar>"
    echo -e "                Path to tar file containing certificate files. By default, the Wazuh installation assistant will search for a file named wazuh-install-files.tar in the same path as the script."
    echo -e ""
    echo -e "        -u,  --uninstall"
    echo -e "                Uninstalls all Wazuh components. This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -V,  --version"
    echo -e "                Shows the version of the script and Wazuh packages."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboard <dashboard-node-name>"
    echo -e "                Install and configure Wazuh dashboard, used for distributed deployments."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer <indexer-node-name>"
    echo -e "                Install and configure Wazuh indexer, used for distributed deployments."
    echo -e ""
    echo -e "        -ws,  --wazuh-server <server-node-name>"
    echo -e "                Install and configure Wazuh manager and Filebeat, used for distributed deployments."
    exit 1

}
function main() {
    umask 177

    if [ -z "${1}" ]; then
        getHelp
    fi

    while [ -n "${1}" ]
    do
        case "${1}" in
            "-a"|"--all-in-one")
                AIO=1
                shift 1
                ;;
            "-c"|"--config-file")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <path-to-config-yml> after -c|--config-file"
                    getHelp
                    exit 1
                fi
                file_conf=1
                config_file="${2}"
                shift 2
                ;;
            "-d"|"--development")
                development=1
                if [ -n "${2}" ] && [[ ! "${2}" =~ ^- ]]; then
                    if [ "${2}" = "pre-release" ] || [ "${2}" = "staging" ]; then
                        devrepo="${2}"
                    else
                        common_logger -e "Error: Invalid value '${2}' after -d|--development. Accepted values are 'pre-release' or 'staging'."
                        getHelp
                        exit 1
                    fi
                    shift 2
                else
                    devrepo="pre-release"
                    shift 1
                fi
                checks_development_source_tag
                repogpg="https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH"
                repobaseurl="https://packages-dev.wazuh.com/${devrepo}"
                reporelease="unstable"
                filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/extensions/elasticsearch/7.x/wazuh-template.json"
                filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.4.tar.gz"
                bucket="packages-dev.wazuh.com"
                repository="${devrepo}"
                ;;

            "-fd"|"--force-install-dashboard")
                force=1
                shift 1
                ;;
            "-g"|"--generate-config-files")
                configurations=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            "-i"|"--ignore-check")
                ignore=1
                shift 1
                ;;
            "-o"|"--overwrite")
                overwrite=1
                shift 1
                ;;
            "-of"|"--offline-installation")
                offline_install=1
                shift 1
                ;;
            "-p"|"--port")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <port> after -p|--port"
                    getHelp
                    exit 1
                fi
                port_specified=1
                port_number="${2}"
                shift 2
                ;;
            "-s"|"--start-cluster")
                start_indexer_cluster=1
                shift 1
                ;;
            "-t"|"--tar")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <path-to-certs-tar> after -t|--tar"
                    getHelp
                    exit 1
                fi
                tar_conf=1
                tar_file="${2}"
                shift 2
                ;;
            "-u"|"--uninstall")
                uninstall=1
                shift 1
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                debug="2>&1 | tee -a ${logfile}"
                shift 1
                ;;
            "-V"|"--version")
                showVersion=1
                shift 1
                ;;
            "-wd"|"--wazuh-dashboard")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -wd|---wazuh-dashboard"
                    getHelp
                    exit 1
                fi
                dashboard=1
                dashname="${2}"
                shift 2
                ;;
            "-wi"|"--wazuh-indexer")
                if [ -z "${2}" ]; then
                    common_logger -e "Arguments contain errors. Probably missing <node-name> after -wi|--wazuh-indexer."
                    getHelp
                    exit 1
                fi
                indexer=1
                indxname="${2}"
                shift 2
                ;;
            "-ws"|"--wazuh-server")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -ws|--wazuh-server"
                    getHelp
                    exit 1
                fi
                wazuh=1
                winame="${2}"
                shift 2
                ;;
            "-dw"|"--download-wazuh")
                if [ "${2}" != "deb" ] && [ "${2}" != "rpm" ]; then
                    common_logger -e "Error on arguments. Probably missing <deb|rpm> after -dw|--download-wazuh"
                    getHelp
                    exit 1
                fi
                download=1
                package_type="${2}"
                shift 2
                ;;
            "-da"|"--download-arch")
                if [ "${2}" != "amd64" ] && [ "${2}" != "x86_64" ] && [ "${2}" != "arm64" ] && [ "${2}" != "aarch64" ]; then
                    common_logger -e "Error on arguments. Probably missing <amd64|x86_64|arm64|aarch64> after -da|--download-arch"
                    getHelp
                    exit 1
                fi
                download_arch=1
                arch="${2}"
                shift 2
                ;;
            *)
                echo "Unknow option: ${1}"
                getHelp
        esac
    done

    cat /dev/null > "${logfile}"

    if [ -z "${download}" ] && [ -z "${showVersion}" ]; then
        common_checkRoot
    fi

    if [ -n "${showVersion}" ]; then
        common_logger "Wazuh version: ${wazuh_version}"
        common_logger "Filebeat version: ${filebeat_version}"
        common_logger "Wazuh installation assistant version: ${wazuh_install_vesion}"
        exit 0
    fi

    common_logger "Starting Wazuh installation assistant. Wazuh version: ${wazuh_version}"
    common_logger "Verbose logging redirected to ${logfile}"

# -------------- Uninstall case  ------------------------------------

    common_checkSystem

    if [ -z "${download}" ]; then
        check_dist
    fi

    if [ -z "${uninstall}" ] && [ -z "${offline_install}" ]; then
        installCommon_installCheckDependencies
    elif [ -n "${offline_install}" ]; then
        offline_checkPrerequisites "wia_offline_dependencies" "${wia_offline_dependencies[@]}"
    fi

    common_checkInstalled
    checks_arguments
    if [ -n "${development}" ]; then
        checks_filebeatURL
    fi
    if [ -n "${uninstall}" ]; then
        installCommon_rollBack
        exit 0
    fi

    checks_arch
    if [ -n "${ignore}" ]; then
        common_logger -w "Hardware checks ignored."
    else
        common_logger "Verifying that your system meets the recommended minimum hardware requirements."
        checks_health
    fi

# -------------- Preliminary checks and Prerequisites --------------------------------

    if [ -z "${configurations}" ] && [ -z "${AIO}" ] && [ -z "${download}" ]; then
        checks_previousCertificate
    fi

    if [ -n "${port_specified}" ]; then
        checks_available_port "${port_number}" "${wazuh_aio_ports[@]}"
        dashboard_changePort "${port_number}"
    elif [ -n "${AIO}" ] || [ -n "${dashboard}" ]; then
        dashboard_changePort "${http_port}"
    fi

    if [ -n "${AIO}" ]; then
        rm -f "${tar_file}"
        checks_ports "${wazuh_aio_ports[@]}"
        installCommon_installPrerequisites "AIO"
    fi

    if [ -n "${indexer}" ]; then
        checks_ports "${wazuh_indexer_ports[@]}"
        installCommon_installPrerequisites "indexer"
    fi

    if [ -n "${wazuh}" ]; then
        checks_ports "${wazuh_manager_ports[@]}"
        installCommon_installPrerequisites "wazuh"
    fi

    if [ -n "${dashboard}" ]; then
        checks_ports "${wazuh_dashboard_port}"
        installCommon_installPrerequisites "dashboard"
    fi


# --------------  Wazuh repo  ----------------------

    # Offline installation case: extract the compressed files
    if [ -n "${offline_install}" ]; then
        offline_checkPreinstallation
        offline_extractFiles
        offline_importGPGKey
    fi

    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        check_curlVersion
        if [ -z "${offline_install}" ]; then
            installCommon_addWazuhRepo
        fi
    fi

# -------------- Configuration creation case  -----------------------

    # Creation certificate case: Only AIO and -g option can create certificates.
    if [ -n "${configurations}" ] || [ -n "${AIO}" ]; then
        common_logger "--- Configuration files ---"
        installCommon_createInstallFiles
    fi

    if [ -z "${configurations}" ] && [ -z "${download}" ]; then
        installCommon_extractConfig
        config_file="/tmp/wazuh-install-files/config.yml"
        cert_readConfig
    fi

    # Distributed architecture: node names must be different
    if [[ -z "${AIO}" && -z "${download}" && ( -n "${indexer}"  || -n "${dashboard}" || -n "${wazuh}" ) ]]; then
        checks_names
    fi

    if [ -n "${configurations}" ]; then
        installCommon_removeWIADependencies
    fi

# -------------- Wazuh indexer case -------------------------------

    if [ -n "${indexer}" ]; then
        common_logger "--- Wazuh indexer ---"
        indexer_install
        indexer_configure
        installCommon_startService "wazuh-indexer"
        indexer_initialize
        installCommon_removeWIADependencies
    fi

# -------------- Start Wazuh indexer cluster case  ------------------

    if [ -n "${start_indexer_cluster}" ]; then
        indexer_startCluster
        installCommon_changePasswords
        installCommon_removeWIADependencies
    fi

# -------------- Wazuh dashboard case  ------------------------------

    if [ -n "${dashboard}" ]; then
        common_logger "--- Wazuh dashboard ----"
        dashboard_install
        dashboard_configure
        installCommon_startService "wazuh-dashboard"
        installCommon_changePasswords
        dashboard_initialize
        installCommon_removeWIADependencies

    fi

# -------------- Wazuh server case  ---------------------------------------

    if [ -n "${wazuh}" ]; then
        common_logger "--- Wazuh server ---"
        manager_install
        manager_configure
        if [ -n "${server_node_types[*]}" ]; then
            manager_startCluster
        fi
        installCommon_startService "wazuh-manager"
        filebeat_install
        filebeat_configure
        installCommon_changePasswords
        installCommon_startService "filebeat"
        installCommon_removeWIADependencies
    fi

# -------------- AIO case  ------------------------------------------

    if [ -n "${AIO}" ]; then

        common_logger "--- Wazuh indexer ---"
        indexer_install
        indexer_configure
        installCommon_startService "wazuh-indexer"
        indexer_initialize
        common_logger "--- Wazuh server ---"
        manager_install
        manager_configure
        installCommon_startService "wazuh-manager"
        filebeat_install
        filebeat_configure
        installCommon_startService "filebeat"
        common_logger "--- Wazuh dashboard ---"
        dashboard_install
        dashboard_configure
        installCommon_startService "wazuh-dashboard"
        installCommon_changePasswords
        dashboard_initializeAIO
        installCommon_removeWIADependencies

    fi

# -------------- Offline case  ------------------------------------------

    if [ -n "${download}" ]; then
        common_logger "--- Download Packages ---"
        offline_download
    fi


# -------------------------------------------------------------------

    if [ -z "${configurations}" ] && [ -z "${download}" ] && [ -z "${offline_install}" ]; then
        installCommon_restoreWazuhrepo
    fi

    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        eval "rm -rf /tmp/wazuh-install-files ${debug}"
        common_logger "Installation finished."
    elif [ -n "${start_indexer_cluster}" ]; then
        common_logger "Wazuh indexer cluster started."
    fi

}

# ------------ filebeat.sh ------------ 
function filebeat_configure(){

    common_logger -d "Configuring Filebeat."

    if [ -z "${offline_install}" ]; then
        eval "common_curl -sSo /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 --retry 5 --retry-delay 5 --fail"
        if [ ! -f "/etc/filebeat/wazuh-template.json" ]; then
            common_logger -e "Error downloading wazuh-template.json file."
            installCommon_rollBack
            exit 1
        fi
        common_logger -d "Filebeat template was download successfully."

        eval "(common_curl -sS ${filebeat_wazuh_module} --max-time 300 --retry 5 --retry-delay 5 --fail | tar -xvz -C /usr/share/filebeat/module) ${debug}"
        if [ ! -d "/usr/share/filebeat/module" ]; then
            common_logger -e "Error downloading wazuh filebeat module."
            installCommon_rollBack
            exit 1
        fi
        common_logger -d "Filebeat module was downloaded successfully."
    else
        eval "cp ${offline_files_path}/wazuh-template.json /etc/filebeat/wazuh-template.json ${debug}"
        eval "tar -xvzf ${offline_files_path}/wazuh-filebeat-*.tar.gz -C /usr/share/filebeat/module ${debug}"
    fi

    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig filebeat/filebeat_assistant.yml /etc/filebeat/filebeat.yml ${debug}"
    else
        eval "installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
        if [ ${#indexer_node_names[@]} -eq 1 ]; then
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            echo "  - ${indexer_node_ips[0]}:9200" >> /etc/filebeat/filebeat.yml
        else
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            for i in "${indexer_node_ips[@]}"; do
                echo "  - ${i}:9200" >> /etc/filebeat/filebeat.yml
            done
        fi
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    filebeat_copyCertificates

    eval "filebeat keystore create ${debug}"
    eval "(echo admin | filebeat keystore add username --force --stdin)" "${debug}"
    eval "(echo admin | filebeat keystore add password --force --stdin)" "${debug}"

    common_logger "Filebeat post-install configuration finished."
}
function filebeat_copyCertificates() {

    common_logger -d "Copying Filebeat certificates."
    if [ -f "${tar_file}" ]; then
        if [ -n "${AIO}" ]; then
            if ! tar -tvf "${tar_file}" | grep -q "${server_node_names[0]}" ; then
                common_logger -e "Tar file does not contain certificate for the node ${server_node_names[0]}."
                installCommon_rollBack
                exit 1
            fi
            eval "sed -i s/filebeat.pem/${server_node_names[0]}.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "sed -i s/filebeat-key.pem/${server_node_names[0]}-key.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} --wildcards wazuh-install-files/${server_node_names[0]}.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} --wildcards wazuh-install-files/${server_node_names[0]}-key.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
            eval "rm -rf ${filebeat_cert_path}/wazuh-install-files/ ${debug}"
        else
            if ! tar -tvf "${tar_file}" | grep -q "${winame}" ; then
                common_logger -e "Tar file does not contain certificate for the node ${winame}."
                installCommon_rollBack
                exit 1
            fi
            eval "sed -i s/filebeat.pem/${winame}.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "sed -i s/filebeat-key.pem/${winame}-key.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/${winame}.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/${winame}-key.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
            eval "rm -rf ${filebeat_cert_path}/wazuh-install-files/ ${debug}"
        fi
        eval "chmod 500 ${filebeat_cert_path} ${debug}"
        eval "chmod 400 ${filebeat_cert_path}/* ${debug}"
        eval "chown root:root ${filebeat_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Filebeat"
        installCommon_rollBack
        exit 1
    fi

}
function filebeat_install() {

    common_logger "Starting Filebeat installation."
    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "filebeat" "${filebeat_version}"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "filebeat" "${filebeat_version}"
    fi

    install_result="${PIPESTATUS[0]}"
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${filebeat_installed}" ]; then
        common_logger -e "Filebeat installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Filebeat installation finished."
    fi

}

# ------------ installCommon.sh ------------ 
function installCommon_addCentOSRepository() {

    local repo_name="$1"
    local repo_description="$2"
    local repo_baseurl="$3"

    echo "[$repo_name]" >> "${centos_repo}"
    echo "name=${repo_description}" >> "${centos_repo}"
    echo "baseurl=${repo_baseurl}" >> "${centos_repo}"
    echo 'gpgcheck=1' >> "${centos_repo}"
    echo 'enabled=1' >> "${centos_repo}"
    echo "gpgkey=file://${centos_key}" >> "${centos_repo}"
    echo '' >> "${centos_repo}"

}
function installCommon_cleanExit() {

    rollback_conf=""

    if [ -n "$spin_pid" ]; then
        eval "kill -9 $spin_pid ${debug}"
    fi

    until [[ "${rollback_conf}" =~ ^[N|Y|n|y]$ ]]; do
        echo -ne "\nDo you want to remove the ongoing installation?[Y/N]"
        read -r rollback_conf
    done
    if [[ "${rollback_conf}" =~ [N|n] ]]; then
        exit 1
    else
        common_checkInstalled
        installCommon_rollBack
        exit 1
    fi

}
function installCommon_addWazuhRepo() {

    common_logger -d "Adding the Wazuh repository."

    if [ -n "${development}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            eval "rm -f /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "rm -f /etc/apt/sources.list.d/wazuh.list ${debug}"
        fi
    fi

    if [ ! -f "/etc/yum.repos.d/wazuh.repo" ] && [ ! -f "/etc/zypp/repos.d/wazuh.repo" ] && [ ! -f "/etc/apt/sources.list.d/wazuh.list" ] ; then
        if [ "${sys_type}" == "yum" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "Cannot import Wazuh GPG key"
                exit 1
            fi
            eval "(echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\${releasever} - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo)" "${debug}"
            eval "chmod 644 /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "common_curl -s ${repogpg} --max-time 300 --retry 5 --retry-delay 5 --fail | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import - ${debug}"
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "Cannot import Wazuh GPG key"
                exit 1
            fi
            eval "chmod 644 /usr/share/keyrings/wazuh.gpg ${debug}"
            eval "(echo \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] ${repobaseurl}/apt/ ${reporelease} main\" | tee /etc/apt/sources.list.d/wazuh.list)" "${debug}"
            eval "apt-get update -q ${debug}"
            eval "chmod 644 /etc/apt/sources.list.d/wazuh.list ${debug}"
        fi
    else
        common_logger -d "Wazuh repository already exists. Skipping addition."
    fi

    if [ -n "${development}" ]; then
        common_logger "Wazuh development repository added."
    else
        common_logger "Wazuh repository added."
    fi
}
function installCommon_aptInstall() {

    package="${1}"
    version="${2}"
    attempt=0
    if [ -n "${version}" ]; then
        installer=${package}${sep}${version}
    else
        installer=${package}
    fi

    # Offline installation case: get package name and install it
    if [ -n "${offline_install}" ]; then
        package_name=$(ls ${offline_packages_path} | grep ${package})
        installer="${offline_packages_path}/${package_name}"
    fi

    command="DEBIAN_FRONTEND=noninteractive apt-get install ${installer} -y -q"
    common_checkAptLock

    if [ "${attempt}" -ne "${max_attempts}" ]; then
        apt_output=$(eval "${command} 2>&1")
        install_result="${PIPESTATUS[0]}"
        eval "echo \${apt_output} ${debug}"
    fi

}
function installCommon_aptInstallList(){

    dependencies=("$@")
    not_installed=()

    for dep in "${dependencies[@]}"; do
        if ! apt list --installed 2>/dev/null | grep -q -E ^"${dep}"\/; then
            not_installed+=("${dep}")
            for wia_dep in "${wia_apt_dependencies[@]}"; do
                if [ "${wia_dep}" == "${dep}" ]; then
                    wia_dependencies_installed+=("${dep}")
                fi
            done
        fi
    done

    if [ "${#not_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ----"
        for dep in "${not_installed[@]}"; do
            common_logger "Installing $dep."
            installCommon_aptInstall "${dep}"
            if [ "${install_result}" != 0 ]; then
                common_logger -e "Cannot install dependency: ${dep}."
                installCommon_rollBack
                exit 1
            fi
        done
    fi

}
function installCommon_changePasswordApi() {

    common_logger -d "Changing API passwords."

    #Change API password tool
    if [ -n "${changeall}" ]; then
        for i in "${!api_passwords[@]}"; do
            if [ -n "${wazuh}" ] || [ -n "${AIO}" ]; then
                passwords_getApiUserId "${api_users[i]}"
                WAZUH_PASS_API='{\"password\":\"'"${api_passwords[i]}"'\"}'
                eval 'common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail'
                if [ "${api_users[i]}" == "${adminUser}" ]; then
                    sleep 1
                    adminPassword="${api_passwords[i]}"
                    passwords_getApiToken
                fi
            fi
            if [ "${api_users[i]}" == "wazuh-wui" ] && { [ -n "${dashboard}" ] || [ -n "${AIO}" ]; }; then
                passwords_changeDashboardApiPassword "${api_passwords[i]}"
            fi
        done
    else
        if [ -n "${wazuh}" ] || [ -n "${AIO}" ]; then
            passwords_getApiUserId "${nuser}"
            WAZUH_PASS_API='{\"password\":\"'"${password}"'\"}'
            eval 'common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail'
        fi
        if [ "${nuser}" == "wazuh-wui" ] && { [ -n "${dashboard}" ] || [ -n "${AIO}" ]; }; then
                passwords_changeDashboardApiPassword "${password}"
        fi
    fi

}
function installCommon_createCertificates() {

    common_logger -d "Creating Wazuh certificates."
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig certificate/config_aio.yml ${config_file} ${debug}"
    fi

    cert_readConfig

    if [ -d /tmp/wazuh-certificates/ ]; then
        eval "rm -rf /tmp/wazuh-certificates/ ${debug}"
    fi
    eval "mkdir /tmp/wazuh-certificates/ ${debug}"

    cert_tmp_path="/tmp/wazuh-certificates/"

    cert_generateRootCAcertificate
    cert_generateAdmincertificate
    cert_generateIndexercertificates
    cert_generateFilebeatcertificates
    cert_generateDashboardcertificates
    cert_cleanFiles
    eval "chmod 400 /tmp/wazuh-certificates/* ${debug}"
    eval "mv /tmp/wazuh-certificates/* /tmp/wazuh-install-files ${debug}"
    eval "rm -rf /tmp/wazuh-certificates/ ${debug}"

}
function installCommon_createClusterKey() {

    openssl rand -hex 16 >> "/tmp/wazuh-install-files/clusterkey"

}
function installCommon_createInstallFiles() {

    if [ -d /tmp/wazuh-install-files ]; then
        eval "rm -rf /tmp/wazuh-install-files ${debug}"
    fi

    if eval "mkdir /tmp/wazuh-install-files ${debug}"; then
        common_logger "Generating configuration files."

        dep="openssl"
        if [ "${sys_type}" == "yum" ]; then
            installCommon_yumInstallList "${dep}"
        elif [ "${sys_type}" == "apt-get" ]; then
            installCommon_aptInstallList "${dep}"
        fi

        if [ "${#not_installed[@]}" -gt 0 ]; then
            wia_dependencies_installed+=("${dep}")
        fi

        if [ -n "${configurations}" ]; then
            cert_checkOpenSSL
        fi
        installCommon_createCertificates
        if [ -n "${server_node_types[*]}" ]; then
            installCommon_createClusterKey
        fi
        gen_file="/tmp/wazuh-install-files/wazuh-passwords.txt"
        passwords_generatePasswordFile
        eval "cp '${config_file}' '/tmp/wazuh-install-files/config.yml' ${debug}"
        eval "chown root:root /tmp/wazuh-install-files/* ${debug}"
        eval "tar -zcf '${tar_file}' -C '/tmp/' wazuh-install-files/ ${debug}"
        eval "rm -rf '/tmp/wazuh-install-files' ${debug}"
	    eval "rm -rf ${config_file} ${debug}"
        common_logger "Created ${tar_file_name}. It contains the Wazuh cluster key, certificates, and passwords necessary for installation."
    else
        common_logger -e "Unable to create /tmp/wazuh-install-files"
        exit 1
    fi
}
function installCommon_changePasswords() {

    common_logger -d "Setting Wazuh indexer cluster passwords."
    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C /tmp wazuh-install-files/wazuh-passwords.txt ${debug}"
        p_file="/tmp/wazuh-install-files/wazuh-passwords.txt"
        common_checkInstalled
        if [ -n "${start_indexer_cluster}" ] || [ -n "${AIO}" ]; then
            changeall=1
            passwords_readUsers
        else
            no_indexer_backup=1
        fi
        if { [ -n "${wazuh}" ] || [ -n "${AIO}" ]; } && { [ "${server_node_types[pos]}" == "master" ] || [ "${#server_node_names[@]}" -eq 1 ]; }; then
            passwords_getApiToken
            passwords_getApiUsers
            passwords_getApiIds
        else
            api_users=( wazuh wazuh-wui )
        fi
        installCommon_readPasswordFileUsers
    else
        common_logger -e "Cannot find passwords file. Exiting"
        installCommon_rollBack
        exit 1
    fi
    if [ -n "${start_indexer_cluster}" ] || [ -n "${AIO}" ]; then
        passwords_getNetworkHost
        passwords_generateHash
    fi

    passwords_changePassword

    if [ -n "${start_indexer_cluster}" ] || [ -n "${AIO}" ]; then
        passwords_runSecurityAdmin
    fi
    if [ -n "${wazuh}" ] || [ -n "${dashboard}" ] || [ -n "${AIO}" ]; then
        if [ "${server_node_types[pos]}" == "master" ] || [ "${#server_node_names[@]}" -eq 1 ] || [ -n "${dashboard_installed}" ]; then
            installCommon_changePasswordApi
        fi
    fi

}
function installCommon_configureCentOSRepositories() {

    centos_repos_configured=1
    centos_key="/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial"
    eval "common_curl -sLo ${centos_key} 'https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official' --max-time 300 --retry 5 --retry-delay 5 --fail"

    if [ ! -f "${centos_key}" ]; then
        common_logger -w "The CentOS key could not be added. Some dependencies may not be installed."
    else
        centos_repo="/etc/yum.repos.d/centos.repo"
        eval "touch ${centos_repo} ${debug}"
        common_logger -d "CentOS repository file created."

        if [ "${DIST_VER}" == "9" ]; then
            installCommon_addCentOSRepository "appstream" "CentOS Stream \$releasever - AppStream" "https://mirror.stream.centos.org/9-stream/AppStream/\$basearch/os/"
            installCommon_addCentOSRepository "baseos" "CentOS Stream \$releasever - BaseOS" "https://mirror.stream.centos.org/9-stream/BaseOS/\$basearch/os/"
        elif [ "${DIST_VER}" == "8" ]; then
            installCommon_addCentOSRepository "extras" "CentOS Linux \$releasever - Extras" "http://vault.centos.org/centos/\$releasever/extras/\$basearch/os/"
            installCommon_addCentOSRepository "baseos" "CentOS Linux \$releasever - BaseOS" "http://vault.centos.org/centos/\$releasever/BaseOS/\$basearch/os/"
            installCommon_addCentOSRepository "appstream" "CentOS Linux \$releasever - AppStream" "http://vault.centos.org/centos/\$releasever/AppStream/\$basearch/os/"
        fi

        common_logger -d "CentOS repositories added."
    fi

}
function installCommon_extractConfig() {

    common_logger -d "Extracting Wazuh configuration."
    if ! tar -tf "${tar_file}" | grep -q wazuh-install-files/config.yml; then
        common_logger -e "There is no config.yml file in ${tar_file}."
        exit 1
    fi
    eval "tar -xf ${tar_file} -C /tmp wazuh-install-files/config.yml ${debug}"

}
function installCommon_getConfig() {

    if [ "$#" -ne 2 ]; then
        common_logger -e "installCommon_getConfig should be called with two arguments"
        exit 1
    fi

    config_name="config_file_$(eval "echo ${1} | sed 's|/|_|g;s|.yml||'")"
    if [ -z "$(eval "echo \${${config_name}}")" ]; then
        common_logger -e "Unable to find configuration file ${1}. Exiting."
        installCommon_rollBack
        exit 1
    fi
    eval "echo \"\${${config_name}}\"" > "${2}"
}
function installCommon_getPass() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "${1}" ]; then
            u_pass=${passwords[i]}
        fi
    done
}
function installCommon_installCheckDependencies() {

    common_logger -d "Installing check dependencies."
    if [ "${sys_type}" == "yum" ]; then
        if [[ "${DIST_NAME}" == "rhel" ]] && [[ "${DIST_VER}" == "8" || "${DIST_VER}" == "9" ]]; then
            installCommon_configureCentOSRepositories
        fi
        installCommon_yumInstallList "${wia_yum_dependencies[@]}"

        # In RHEL cases, remove the CentOS repositories configuration
        if [ "${centos_repos_configured}" == 1 ]; then
            installCommon_removeCentOSrepositories
        fi

    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt-get update -q ${debug}"
        installCommon_aptInstallList "${wia_apt_dependencies[@]}"
    fi

}
function installCommon_installPrerequisites() {

    message="Installing prerequisites dependencies."
    if [ "${sys_type}" == "yum" ]; then
        if [ "${1}" == "AIO" ]; then
            deps=($(echo "${indexer_yum_dependencies[@]}" "${dashboard_yum_dependencies[@]}" | tr ' ' '\n' | sort -u))
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_yumInstallList "${deps[@]}"
            else
                offline_checkPrerequisites "${deps[@]}"
            fi
        fi
        if [ "${1}" == "indexer" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_yumInstallList "${indexer_yum_dependencies[@]}"
            else
                offline_checkPrerequisites "${indexer_yum_dependencies[@]}"
            fi
        fi
        if [ "${1}" == "dashboard" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_yumInstallList "${dashboard_yum_dependencies[@]}"
            else
                offline_checkPrerequisites "${dashboard_yum_dependencies[@]}"
            fi
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        if [ -z "${offline_install}" ]; then
            eval "apt-get update -q ${debug}"
        fi
        if [ "${1}" == "AIO" ]; then
            deps=($(echo "${wazuh_apt_dependencies[@]}" "${indexer_apt_dependencies[@]}" "${dashboard_apt_dependencies[@]}" | tr ' ' '\n' | sort -u))
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${deps[@]}"
            else
                offline_checkPrerequisites "${deps[@]}"
            fi
        fi
        if [ "${1}" == "indexer" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${indexer_apt_dependencies[@]}"
            else
                offline_checkPrerequisites "${indexer_apt_dependencies[@]}"
            fi
        fi
        if [ "${1}" == "dashboard" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${dashboard_apt_dependencies[@]}"
            else
                offline_checkPrerequisites "${dashboard_apt_dependencies[@]}"
            fi
        fi
        if [ "${1}" == "wazuh" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${wazuh_apt_dependencies[@]}"
            else
                offline_checkPrerequisites "${wazuh_apt_dependencies[@]}"
            fi
        fi
    fi

}
function installCommon_readPasswordFileUsers() {

    filecorrect=$(grep -Ev '^#|^\s*$' "${p_file}" | grep -Pzc "\A(\s*(indexer_username|api_username|indexer_password|api_password):[ \t]+[\'\"]?[\w.*+?-]+[\'\"]?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The password file does not have a correct format or password uses invalid characters. Allowed characters: A-Za-z0-9.*+?

For Wazuh indexer users, the file must have this format:

# Description
  indexer_username: <user>
  indexer_password: <password>

For Wazuh API users, the file must have this format:

# Description
  api_username: <user>
  api_password: <password>

"
	    installCommon_rollBack
        exit 1
    fi

    sfileusers=$(grep indexer_username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")
    sfilepasswords=$(grep indexer_password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")

    sfileapiusers=$(grep api_username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")
    sfileapipasswords=$(grep api_password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")


    mapfile -t fileusers < <(printf '%s\n' "${sfileusers}")
    mapfile -t filepasswords < <(printf '%s\n' "${sfilepasswords}")
    mapfile -t fileapiusers < <(printf '%s\n' "${sfileapiusers}")
    mapfile -t fileapipasswords < <(printf '%s\n' "${sfileapipasswords}")

    if [ -n "${changeall}" ]; then
        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ ${users[i]} == "${fileusers[j]}" ]]; then
                    passwords_checkPassword "${filepasswords[j]}"
                    passwords[i]=${filepasswords[j]}
                    supported=true
                fi
            done
            if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done

        for j in "${!fileapiusers[@]}"; do
            supported=false
            for i in "${!api_users[@]}"; do
                if [[ "${api_users[i]}" == "${fileapiusers[j]}" ]]; then
                    passwords_checkPassword "${fileapipasswords[j]}"
                    api_passwords[i]=${fileapipasswords[j]}
                    supported=true
                fi
            done
            if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The Wazuh API user ${fileapiusers[j]} does not exist"
            fi
        done
    else
        finalusers=()
        finalpasswords=()

        finalapiusers=()
        finalapipasswords=()

        if [ -n "${dashboard_installed}" ] &&  [ -n "${dashboard}" ]; then
            users=( kibanaserver admin )
        fi

        if [ -n "${filebeat_installed}" ] && [ -n "${wazuh}" ]; then
            users=( admin )
        fi

        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    passwords_checkPassword "${filepasswords[j]}"
                    finalusers+=(${fileusers[j]})
                    finalpasswords+=(${filepasswords[j]})
                    supported=true
                fi
            done
            if [ "${supported}" = "false" ] && [ -n "${indexer_installed}" ] && [ -n "${changeall}" ]; then
                common_logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done

        for j in "${!fileapiusers[@]}"; do
            supported=false
            for i in "${!api_users[@]}"; do
                if [[ "${api_users[i]}" == "${fileapiusers[j]}" ]]; then
                    passwords_checkPassword "${fileapipasswords[j]}"
                    finalapiusers+=("${fileapiusers[j]}")
                    finalapipasswords+=("${fileapipasswords[j]}")
                    supported=true
                fi
            done
            if [ ${supported} = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The Wazuh API user ${fileapiusers[j]} does not exist"
            fi
        done

        users=()
        mapfile -t users < <(printf '%s\n' "${finalusers[@]}")
        mapfile -t passwords < <(printf '%s\n' "${finalpasswords[@]}")
        mapfile -t api_users < <(printf '%s\n' "${finalapiusers[@]}")
        mapfile -t api_passwords < <(printf '%s\n' "${finalapipasswords[@]}")
        changeall=1
    fi

}
function installCommon_restoreWazuhrepo() {

    common_logger -d "Restoring Wazuh repository."
    if [ -n "${development}" ]; then
        if [ "${sys_type}" == "yum" ] && [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
            file="/etc/yum.repos.d/wazuh.repo"
        elif [ "${sys_type}" == "apt-get" ] && [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
            file="/etc/apt/sources.list.d/wazuh.list"
        else
            common_logger -w -d "Wazuh repository does not exists."
        fi
        eval "sed -i 's/-dev//g' ${file} ${debug}"
        eval "sed -i 's/pre-release/4.x/g' ${file} ${debug}"
        eval "sed -i 's/unstable/stable/g' ${file} ${debug}"
    fi

}
function installCommon_removeCentOSrepositories() {

    eval "rm -f ${centos_repo} ${debug}"
    eval "rm -f ${centos_key} ${debug}"
    eval "yum clean all ${debug}"
    centos_repos_configured=0
    common_logger -d "CentOS repositories and key deleted."

}
function installCommon_rollBack() {

    if [ -z "${uninstall}" ]; then
        common_logger "--- Removing existing Wazuh installation ---"
    fi

    if [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo ${debug}"
    elif [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo ${debug}"
    elif [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list ${debug}"
    fi

    if [[ -n "${wazuh_installed}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]];then
        common_logger "Removing Wazuh manager."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-manager -y ${debug}"
                eval "rpm -q wazuh-manager --quiet && wazuh_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge wazuh-manager -y ${debug}"
            wazuh_failed_uninstall=$(apt list --installed 2>/dev/null | grep wazuh-manager)
        fi

        if [ -n "${wazuh_failed_uninstall}" ]; then
            common_logger -w "The Wazuh manager package could not be removed."
        else
            common_logger "Wazuh manager removed."
        fi

    fi

    if [[ ( -n "${wazuh_remaining_files}"  || -n "${wazuh_installed}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [[ -n "${indexer_installed}" && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh indexer."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-indexer -y ${debug}"
                eval "rpm -q wazuh-indexer --quiet && indexer_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge wazuh-indexer -y ${debug}"
            indexer_failed_uninstall=$(apt list --installed 2>/dev/null | grep wazuh-indexer)
        fi

        if [ -n "${indexer_failed_uninstall}" ]; then
            common_logger -w "The Wazuh indexer package could not be removed."
        else
            common_logger "Wazuh indexer removed."
        fi
    fi

    if [[ ( -n "${indexer_remaining_files}" || -n "${indexer_installed}" ) && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-indexer/ ${debug}"
        eval "rm -rf /usr/share/wazuh-indexer/ ${debug}"
        eval "rm -rf /etc/wazuh-indexer/ ${debug}"
    fi

    if [[ -n "${filebeat_installed}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Filebeat."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove filebeat -y ${debug}"
                eval "rpm -q filebeat --quiet && filebeat_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge filebeat -y ${debug}"
            filebeat_failed_uninstall=$(apt list --installed 2>/dev/null | grep filebeat)
        fi

        if [ -n "${filebeat_failed_uninstall}" ]; then
            common_logger -w "The Filebeat package could not be removed."
        else
            common_logger "Filebeat removed."
        fi
    fi

    if [[ ( -n "${filebeat_remaining_files}" || -n "${filebeat_installed}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [[ -n "${dashboard_installed}" && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh dashboard."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-dashboard -y ${debug}"
                eval "rpm -q wazuh-dashboard --quiet && dashboard_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge wazuh-dashboard -y ${debug}"
            dashboard_failed_uninstall=$(apt list --installed 2>/dev/null | grep wazuh-dashboard)
        fi

        if [ -n "${dashboard_failed_uninstall}" ]; then
            common_logger -w "The Wazuh dashboard package could not be removed."
        else
            common_logger "Wazuh dashboard removed."
        fi
    fi

    if [[ ( -n "${dashboard_remaining_files}" || -n "${dashboard_installed}" ) && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-dashboard/ ${debug}"
        eval "rm -rf /usr/share/wazuh-dashboard/ ${debug}"
        eval "rm -rf /etc/wazuh-dashboard/ ${debug}"
        eval "rm -rf /run/wazuh-dashboard/ ${debug}"
    fi

    elements_to_remove=(    "/var/log/wazuh-indexer/"
                            "/var/log/filebeat/"
                            "/etc/systemd/system/opensearch.service.wants/"
                            "/securityadmin_demo.sh"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service"
                            "/etc/systemd/system/multi-user.target.wants/filebeat.service"
                            "/etc/systemd/system/multi-user.target.wants/opensearch.service"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-dashboard.service"
                            "/etc/systemd/system/wazuh-dashboard.service"
                            "/lib/firewalld/services/dashboard.xml"
                            "/lib/firewalld/services/opensearch.xml" )

    eval "rm -rf ${elements_to_remove[*]} ${debug}"

    common_remove_gpg_key

    installCommon_removeWIADependencies

    eval "systemctl daemon-reload ${debug}"

    if [ -z "${uninstall}" ]; then
        if [ -n "${rollback_conf}" ] || [ -n "${overwrite}" ]; then
            common_logger "Installation cleaned."
        else
            common_logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
        fi
    fi

}
function installCommon_startService() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "installCommon_startService must be called with 1 argument."
        exit 1
    fi

    common_logger "Starting service ${1}."

    if [[ -d /run/systemd/system ]]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable ${1}.service ${debug}"
        eval "systemctl start ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        eval "chkconfig ${1} on ${debug}"
        eval "service ${1} start ${debug}"
        eval "/etc/init.d/${1} start ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    else
        common_logger -e "${1} could not start. No service manager found on the system."
        exit 1
    fi

}
function installCommon_yumInstallList(){

    dependencies=("$@")
    not_installed=()
    for dep in "${dependencies[@]}"; do
        if ! rpm -q "${dep}" --quiet;then
            not_installed+=("${dep}")
            for wia_dep in "${wia_yum_dependencies[@]}"; do
                if [ "${wia_dep}" == "${dep}" ]; then
                    wia_dependencies_installed+=("${dep}")
                fi
            done
        fi
    done

    if [ "${#not_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ---"
        for dep in "${not_installed[@]}"; do
            common_logger "Installing $dep."
            installCommon_yumInstall "${dep}"
            yum_code="${PIPESTATUS[0]}"

            eval "echo \${yum_output} ${debug}"
            if [  "${yum_code}" != 0  ]; then
                common_logger -e "Cannot install dependency: ${dep}."
                installCommon_rollBack
                exit 1
            fi
        done
    fi

}
function installCommon_removeWIADependencies() {

    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumRemoveWIADependencies
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptRemoveWIADependencies
    fi

}
function installCommon_yumRemoveWIADependencies(){

    if [ "${#wia_dependencies_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ---"
        for dep in "${wia_dependencies_installed[@]}"; do
            if [ "${dep}" != "systemd" ]; then
                common_logger "Removing $dep."
                yum_output=$(yum remove ${dep} -y 2>&1)
                yum_code="${PIPESTATUS[0]}"

                eval "echo \${yum_output} ${debug}"
                if [  "${yum_code}" != 0  ]; then
                    common_logger -e "Cannot remove dependency: ${dep}."
                    exit 1
                fi
            fi
        done
    fi

}
function installCommon_aptRemoveWIADependencies(){

    if [ "${#wia_dependencies_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ----"
        for dep in "${wia_dependencies_installed[@]}"; do
            if [ "${dep}" != "systemd" ]; then
                common_logger "Removing $dep."
                apt_output=$(apt-get remove --purge ${dep} -y 2>&1)
                apt_code="${PIPESTATUS[0]}"

                eval "echo \${apt_output} ${debug}"
                if [  "${apt_code}" != 0  ]; then
                    common_logger -e "Cannot remove dependency: ${dep}."
                    exit 1
                fi
            fi
        done
    fi

}
function installCommon_yumInstall() {

    package="${1}"
    version="${2}"
    install_result=1
    if [ -n "${version}" ]; then
        installer="${package}-${version}"
    else
        installer="${package}"
    fi

    # Offline installation case: get package name and install it
    if [ -n "${offline_install}" ]; then
        package_name=$(ls ${offline_packages_path} | grep ${package})
        installer="${offline_packages_path}/${package_name}"
        command="rpm -ivh ${installer}"
        common_logger -d "Installing local package: ${installer}"
    else
        command="yum install ${installer} -y"
    fi
    common_checkYumLock

    if [ "${attempt}" -ne "${max_attempts}" ]; then
        yum_output=$(eval "${command} 2>&1")
        install_result="${PIPESTATUS[0]}"
        eval "echo \${yum_output} ${debug}"
    fi

}
function installCommon_checkAptLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while fuser "${apt_lockfile}" >/dev/null 2>&1 && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using APT. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}

# ------------ manager.sh ------------ 
function manager_startCluster() {

    common_logger -d "Starting Wazuh manager cluster."
    for i in "${!server_node_names[@]}"; do
        if [[ "${server_node_names[i]}" == "${winame}" ]]; then
            pos="${i}";
        fi
    done

    for i in "${!server_node_types[@]}"; do
        if [[ "${server_node_types[i],,}" == "master" ]]; then
            master_address=${server_node_ips[i]}
        fi
    done

    key=$(tar -axf "${tar_file}" wazuh-install-files/clusterkey -O)
    bind_address="0.0.0.0"
    port="1516"
    hidden="no"
    disabled="no"
    lstart=$(grep -n "<cluster>" /var/ossec/etc/ossec.conf | cut -d : -f 1)
    lend=$(grep -n "</cluster>" /var/ossec/etc/ossec.conf | cut -d : -f 1)

    eval 'sed -i -e "${lstart},${lend}s/<name>.*<\/name>/<name>wazuh_cluster<\/name>/" \
        -e "${lstart},${lend}s/<node_name>.*<\/node_name>/<node_name>${winame}<\/node_name>/" \
        -e "${lstart},${lend}s/<node_type>.*<\/node_type>/<node_type>${server_node_types[pos],,}<\/node_type>/" \
        -e "${lstart},${lend}s/<key>.*<\/key>/<key>${key}<\/key>/" \
        -e "${lstart},${lend}s/<port>.*<\/port>/<port>${port}<\/port>/" \
        -e "${lstart},${lend}s/<bind_addr>.*<\/bind_addr>/<bind_addr>${bind_address}<\/bind_addr>/" \
        -e "${lstart},${lend}s/<node>.*<\/node>/<node>${master_address}<\/node>/" \
        -e "${lstart},${lend}s/<hidden>.*<\/hidden>/<hidden>${hidden}<\/hidden>/" \
        -e "${lstart},${lend}s/<disabled>.*<\/disabled>/<disabled>${disabled}<\/disabled>/" \
        /var/ossec/etc/ossec.conf'

}
function manager_configure(){

    common_logger -d "Configuring Wazuh manager."

    if [ ${#indexer_node_names[@]} -eq 1 ]; then
        eval "sed -i 's/<host>.*<\/host>/<host>https:\/\/${indexer_node_ips[0]}:9200<\/host>/g' /var/ossec/etc/ossec.conf ${debug}"
    else
        lstart=$(grep -n "<hosts>" /var/ossec/etc/ossec.conf | cut -d : -f 1)
        lend=$(grep -n "</hosts>" /var/ossec/etc/ossec.conf | cut -d : -f 1)
        for i in "${!indexer_node_ips[@]}"; do
            if [ $i -eq 0 ]; then
                eval "sed -i 's/<host>.*<\/host>/<host>https:\/\/${indexer_node_ips[0]}:9200<\/host>/g' /var/ossec/etc/ossec.conf ${debug}"
            else
                eval "sed -i '/<hosts>/a\      <host>https:\/\/${indexer_node_ips[$i]}:9200<\/host>' /var/ossec/etc/ossec.conf"
            fi
        done
    fi
    eval "sed -i s/filebeat.pem/${server_node_names[0]}.pem/ /var/ossec/etc/ossec.conf ${debug}"
    eval "sed -i s/filebeat-key.pem/${server_node_names[0]}-key.pem/ /var/ossec/etc/ossec.conf ${debug}"
    common_logger -d "Setting provisional Wazuh indexer password."
    eval "/var/ossec/bin/wazuh-keystore -f indexer -k username -v admin"
    eval "/var/ossec/bin/wazuh-keystore -f indexer -k password -v admin"
    common_logger "Wazuh manager vulnerability detection configuration finished."
}
function manager_install() {

    common_logger "Starting the Wazuh manager installation."
    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "wazuh-manager" "${wazuh_version}-*"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "wazuh-manager" "${wazuh_version}-*"
    fi

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${wazuh_installed}" ]; then
        common_logger -e "Wazuh installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh manager installation finished."
    fi
}

# ------------ wazuh-offline-installation.sh ------------ 
function offline_checkPrerequisites(){

    dependencies=( "${@}" )
    if [ $1 == "wia_offline_dependencies" ]; then
        dependencies=( "${@:2}" )
        common_logger "Checking dependencies for Wazuh installation assistant."
    else
        common_logger "Checking prerequisites for Offline installation."
    fi

    for dep in "${dependencies[@]}"; do
        if [ "${sys_type}" == "yum" ]; then
            eval "yum list installed 2>/dev/null | grep -q -E ^"${dep}"\\."
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt list --installed 2>/dev/null | grep -q -E ^"${dep}"\/"
        fi

        if [ "${PIPESTATUS[0]}" != 0 ]; then
            common_logger -e "${dep} is necessary for the offline installation."
            exit 1
        fi
    done
    if [ $1 == "wia_offline_dependencies" ]; then
        common_logger -d "Dependencies for Wazuh installation assistant are installed."
    else
        common_logger -d "Prerequisites for Offline installation are installed."
    fi
}
function offline_checkPreinstallation() {

    offline_tarfile="${base_dest_folder}.tar.gz"
    common_logger "Checking ${offline_tarfile} file."
    if [ ! -f "${base_path}/${offline_tarfile}" ]; then
        common_logger -e "The ${offline_tarfile} file was not found in ${base_path}."
        exit 1
    fi
    common_logger -d "${offline_tarfile} was found correctly."

}
function offline_extractFiles() {

    common_logger -d "Extracting files from ${offline_tarfile}"
    if [ ! -d "${base_path}/wazuh-offline/" ]; then
        eval "tar -xzf ${offline_tarfile} ${debug}"

        if [ ! -d "${base_path}/wazuh-offline/" ]; then
            common_logger -e "The ${offline_tarfile} file could not be decompressed."
            exit 1
        fi
    fi

    offline_files_path="${base_path}/wazuh-offline/wazuh-files"
    offline_packages_path="${base_path}/wazuh-offline/wazuh-packages"

    required_files=(
        "${offline_files_path}/filebeat.yml"
        "${offline_files_path}/GPG-KEY-WAZUH"
        "${offline_files_path}/wazuh-filebeat-*.tar.gz"
        "${offline_files_path}/wazuh-template.json"
    )

    if [ "${sys_type}" == "apt-get" ]; then
        required_files+=("${offline_packages_path}/filebeat_*.deb" "${offline_packages_path}/wazuh-dashboard_*.deb" "${offline_packages_path}/wazuh-indexer_*.deb" "${offline_packages_path}/wazuh-manager_*.deb")
    elif [ "${sys_type}" == "rpm" ]; then
        required_files+=("${offline_packages_path}/filebeat-*.rpm" "${offline_packages_path}/wazuh-dashboard_*.rpm" "${offline_packages_path}/wazuh-indexer_*.rpm" "${offline_packages_path}/wazuh-manager_*.rpm")
    fi

    for file in "${required_files[@]}"; do
        if ! compgen -G "${file}" > /dev/null; then
            common_logger -e "Missing necessary offline file: ${file}"
            exit 1
        fi
    done

    common_logger -d "Offline files extracted successfully."
}
function offline_importGPGKey() {

    common_logger -d "Importing Wazuh GPG key."
    if [ "${sys_type}" == "yum" ]; then
        eval "rpm --import ${offline_files_path}/GPG-KEY-WAZUH ${debug}"
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            common_logger -e "Cannot import Wazuh GPG key"
            exit 1
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "gpg --import ${offline_files_path}/GPG-KEY-WAZUH ${debug}"
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            common_logger -e "Cannot import Wazuh GPG key"
            exit 1
        fi
        eval "chmod 644 ${offline_files_path}/GPG-KEY-WAZUH ${debug}"
    fi

}

# ------------ wazuh-offline-download.sh ------------ 
function offline_download() {

  common_logger "Starting Wazuh packages download."
  common_logger "Downloading Wazuh ${package_type} packages for ${arch}."
  dest_path="${base_dest_folder}/wazuh-packages"

  if [ -d "${dest_path}" ]; then
    eval "rm -f ${dest_path}/* ${debug}" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path} ${debug}"
  else
    eval "mkdir -m700 -p ${dest_path} ${debug}" # Create folder if it does not exist
  fi

  packages_to_download=( "manager" "filebeat" "indexer" "dashboard" )

  manager_revision="1"
  indexer_revision="1"
  dashboard_revision="1"
  filebeat_revision="1"

  if [ -n "${development}" ]; then
    filebeat_config_file="https://${bucket}/${wazuh_major}/tpl/wazuh/filebeat/filebeat.yml"
    if [ "${package_type}" == "rpm" ]; then
      manager_rpm_base_url="${repobaseurl}/yum"
      indexer_rpm_base_url="${repobaseurl}/yum"
      dashboard_rpm_base_url="${repobaseurl}/yum"
      filebeat_rpm_base_url="${repobaseurl}/yum"
    elif [ "${package_type}" == "deb" ]; then
      manager_deb_base_url="${repobaseurl}/apt/pool/main/w/wazuh-manager"
      indexer_deb_base_url="${repobaseurl}/apt/pool/main/w/wazuh-indexer"
      dashboard_deb_base_url="${repobaseurl}/apt/pool/main/w/wazuh-dashboard"
      filebeat_deb_base_url="${repobaseurl}/apt/pool/main/f/filebeat"
    fi
  fi

  if [ "${package_type}" == "rpm" ]; then
    manager_rpm_package="wazuh-manager-${wazuh_version}-${manager_revision}.${arch}.${package_type}"
    indexer_rpm_package="wazuh-indexer-${wazuh_version}-${indexer_revision}.${arch}.${package_type}"
    dashboard_rpm_package="wazuh-dashboard-${wazuh_version}-${dashboard_revision}.${arch}.${package_type}"
    filebeat_rpm_package="filebeat-${offline_filebeat_version}-${filebeat_revision}.${arch}.${package_type}"
    manager_base_url="${manager_rpm_base_url}"
    indexer_base_url="${indexer_rpm_base_url}"
    dashboard_base_url="${dashboard_rpm_base_url}"
    filebeat_base_url="${filebeat_rpm_base_url}"
    manager_package="${manager_rpm_package}"
    indexer_package="${indexer_rpm_package}"
    dashboard_package="${dashboard_rpm_package}"
    filebeat_package="${filebeat_rpm_package}"
  elif [ "${package_type}" == "deb" ]; then
    manager_deb_package="wazuh-manager_${wazuh_version}-${manager_revision}_${arch}.${package_type}"
    indexer_deb_package="wazuh-indexer_${wazuh_version}-${indexer_revision}_${arch}.${package_type}"
    dashboard_deb_package="wazuh-dashboard_${wazuh_version}-${dashboard_revision}_${arch}.${package_type}"
    filebeat_deb_package="filebeat_${offline_filebeat_version}-${filebeat_revision}_${arch}.${package_type}"
    manager_base_url="${manager_deb_base_url}"
    indexer_base_url="${indexer_deb_base_url}"
    dashboard_base_url="${dashboard_deb_base_url}"
    filebeat_base_url="${filebeat_deb_base_url}"
    manager_package="${manager_deb_package}"
    indexer_package="${indexer_deb_package}"
    dashboard_package="${dashboard_deb_package}"
    filebeat_package="${filebeat_deb_package}"
  else
    common_logger "Unsupported package type: ${package_type}"
    exit 1
  fi

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${manager_base_url}/${manager_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    manager_revision=$((manager_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      manager_rpm_package="wazuh-manager-${wazuh_version}-${manager_revision}.${arch}.rpm"
      manager_package="${manager_rpm_package}"
    else
      manager_deb_package="wazuh-manager_${wazuh_version}-${manager_revision}_${arch}.deb"
      manager_package="${manager_deb_package}"
    fi
  done
  if [ "$manager_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${manager_base_url}/${manager_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    manager_revision=$((manager_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      manager_rpm_package="wazuh-manager-${wazuh_version}-${manager_revision}.${arch}.rpm"
    else
      manager_deb_package="wazuh-manager_${wazuh_version}-${manager_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Wazuh manager package revision fetched."

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${filebeat_base_url}/${filebeat_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    filebeat_revision=$((filebeat_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      filebeat_rpm_package="filebeat-${offline_filebeat_version}-${filebeat_revision}.${arch}.rpm"
      filebeat_package="${filebeat_rpm_package}"
    else
      filebeat_deb_package="filebeat_${offline_filebeat_version}-${filebeat_revision}_${arch}.deb"
      filebeat_package="${filebeat_deb_package}"
    fi
  done
  if [ "$filebeat_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${filebeat_base_url}/${filebeat_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    filebeat_revision=$((filebeat_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      filebeat_rpm_package="filebeat-${offline_filebeat_version}-${filebeat_revision}.${arch}.rpm"
    else
      filebeat_deb_package="filebeat_${offline_filebeat_version}-${filebeat_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Filebeat package revision fetched."

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${indexer_base_url}/${indexer_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    indexer_revision=$((indexer_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      indexer_rpm_package="wazuh-indexer-${wazuh_version}-${indexer_revision}.${arch}.rpm"
      indexer_package="${indexer_rpm_package}"
    else
      indexer_deb_package="wazuh-indexer_${wazuh_version}-${indexer_revision}_${arch}.deb"
      indexer_package="${indexer_deb_package}"
    fi
  done
  if [ "$indexer_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${indexer_base_url}/${indexer_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    indexer_revision=$((indexer_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      indexer_rpm_package="wazuh-indexer-${wazuh_version}-${indexer_revision}.${arch}.rpm"
    else
      indexer_deb_package="wazuh-indexer_${wazuh_version}-${indexer_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Wazuh indexer package revision fetched."

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${dashboard_base_url}/${dashboard_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    dashboard_revision=$((dashboard_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      dashboard_rpm_package="wazuh-dashboard-${wazuh_version}-${dashboard_revision}.${arch}.rpm"
      dashboard_package="${dashboard_rpm_package}"
    else
      dashboard_deb_package="wazuh-dashboard_${wazuh_version}-${dashboard_revision}_${arch}.deb"
      dashboard_package="${dashboard_deb_package}"
    fi
  done
  if [ "$dashboard_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${dashboard_base_url}/${dashboard_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    dashboard_revision=$((dashboard_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      dashboard_rpm_package="wazuh-dashboard-${wazuh_version}-${dashboard_revision}.${arch}.rpm"
    else
      dashboard_deb_package="wazuh-dashboard_${wazuh_version}-${dashboard_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Wazuh dashboard package revision fetched."

  for package in "${packages_to_download[@]}"
  do
    common_logger -d "Downloading Wazuh ${package} package..."
    package_name="${package}_${package_type}_package"
    eval "package_base_url=${package}_${package_type}_base_url"

    if output=$(common_curl -sSo "${dest_path}/${!package_name}" "${!package_base_url}/${!package_name}" --max-time 300 --retry 5 --retry-delay 5 --fail 2>&1); then
      common_logger "The ${package} package was downloaded."
    else
      common_logger -e "The ${package} package could not be downloaded. Exiting."
      eval "echo \${output} ${debug}"
      exit 1
    fi

  done

  common_logger "The packages are in ${dest_path}"

# --------------------------------------------------

  common_logger "Downloading configuration files and assets."
  dest_path="${base_dest_folder}/wazuh-files"

  if [ -d "${dest_path}" ]; then
    eval "rm -f ${dest_path}/* ${debug}" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path} ${debug}"
  else
    eval "mkdir -m700 -p ${dest_path} ${debug}" # Create folder if it does not exist
  fi

  files_to_download=( "${wazuh_gpg_key}" "${filebeat_config_file}" "${filebeat_wazuh_template}" "${filebeat_wazuh_module}" )

  eval "cd ${dest_path}"
  for file in "${files_to_download[@]}"
  do
    common_logger -d "Downloading ${file}..."
    if output=$(common_curl -sSO ${file} --max-time 300 --retry 5 --retry-delay 5 --fail 2>&1); then
        common_logger "The resource ${file} was downloaded."
    else
        common_logger -e "The resource ${file} could not be downloaded. Exiting."
        eval "echo \${output} ${debug}"
        exit 1
    fi

  done
  eval "cd - > /dev/null"

  eval "chmod 500 ${base_dest_folder} ${debug}"

  common_logger "The configuration files and assets are in wazuh-offline.tar.gz"

  eval "tar -czf ${base_dest_folder}.tar.gz ${base_dest_folder} ${debug}"
  eval "chmod -R 700 ${base_dest_folder} && rm -rf ${base_dest_folder} ${debug}"

  common_logger "You can follow the installation guide here https://documentation.wazuh.com/current/deployment-options/offline-installation.html"

}
# ------------ indexer.sh ------------ 
function indexer_configure() {

    common_logger -d "Configuring Wazuh indexer."
    eval "export JAVA_HOME=/usr/share/wazuh-indexer/jdk/"

    # Configure JVM options for Wazuh indexer
    ram_gb=$(free -m | awk 'FNR == 2 {print $2}')
    ram="$(( ram_mb / 2 ))"

    if [ "${ram}" -eq "0" ]; then
        ram=1024;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"

    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig indexer/indexer_all_in_one.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
    else
        eval "installCommon_getConfig indexer/indexer_assistant_distributed.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            pos=0
            {
            echo "node.name: ${indxname}"
            echo "network.host: ${indexer_node_ips[0]}"
            echo "cluster.initial_master_nodes: ${indxname}"
            echo "plugins.security.nodes_dn:"
            echo '        - CN='"${indxname}"',OU=Wazuh,O=Wazuh,L=California,C=US'
            } >> /etc/wazuh-indexer/opensearch.yml
        else
            echo "node.name: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml
            echo "cluster.initial_master_nodes:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                echo "        - ${i}" >> /etc/wazuh-indexer/opensearch.yml
            done

            echo "discovery.seed_hosts:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_ips[@]}"; do
                echo "        - ${i}" >> /etc/wazuh-indexer/opensearch.yml
            done

            for i in "${!indexer_node_names[@]}"; do
                if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
                    pos="${i}";
                fi
            done

            echo "network.host: ${indexer_node_ips[pos]}" >> /etc/wazuh-indexer/opensearch.yml

            echo "plugins.security.nodes_dn:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                    echo "        - CN=${i},OU=Wazuh,O=Wazuh,L=California,C=US" >> /etc/wazuh-indexer/opensearch.yml
            done
        fi
    fi

    indexer_copyCertificates

    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        {
        echo "wazuh-indexer hard nproc 4096"
        echo "wazuh-indexer soft nproc 4096"
        echo "wazuh-indexer hard nproc 4096"
        echo "wazuh-indexer soft nproc 4096"
        } >> /etc/security/limits.conf
        echo -ne "\nbootstrap.system_call_filter: false" >> /etc/wazuh-indexer/opensearch.yml
    fi

    common_logger "Wazuh indexer post-install configuration finished."
}
function indexer_copyCertificates() {

    common_logger -d "Copying Wazuh indexer certificates."
    eval "rm -f ${indexer_cert_path}/* ${debug}"
    name=${indexer_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${name}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${name}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${indexer_cert_path} ${debug}"
        eval "sed -i s/indexer.pem/${name}.pem/ /etc/wazuh-indexer/opensearch.yml ${debug}"
        eval "sed -i s/indexer-key.pem/${name}-key.pem/ /etc/wazuh-indexer/opensearch.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${name}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${name}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin-key.pem --strip-components 1 ${debug}"
        eval "rm -rf ${indexer_cert_path}/wazuh-install-files/ ${debug}"
        eval "chown -R wazuh-indexer:wazuh-indexer ${indexer_cert_path} ${debug}"
        eval "chmod 500 ${indexer_cert_path} ${debug}"
        eval "chmod 400 ${indexer_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Wazuh indexer"
        installCommon_rollBack
        exit 1;
    fi

}
function indexer_initialize() {

    common_logger "Initializing Wazuh indexer cluster security settings."
    eval "common_curl -XGET https://"${indexer_node_ips[pos]}":9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null"
    e_code="${PIPESTATUS[0]}"

    if [ "${e_code}" -ne "0" ]; then
        common_logger -e "Cannot initialize Wazuh indexer cluster."
        installCommon_rollBack
        exit 1
    fi

    if [ -n "${AIO}" ]; then
        eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/wazuh-indexer/opensearch-security -icl -p 9200 -nhnv -cacert ${indexer_cert_path}/root-ca.pem -cert ${indexer_cert_path}/admin.pem -key ${indexer_cert_path}/admin-key.pem -h 127.0.0.1 ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "The Wazuh indexer cluster security configuration could not be initialized."
            installCommon_rollBack
            exit 1
        else
            common_logger "Wazuh indexer cluster security configuration initialized."
        fi
    fi

    if [ "${#indexer_node_names[@]}" -eq 1 ] && [ -z "${AIO}" ]; then
        installCommon_changePasswords
    fi

    common_logger "Wazuh indexer cluster initialized."

}
function indexer_install() {

    common_logger "Starting Wazuh indexer installation."

    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "wazuh-indexer" "${wazuh_version}-*"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "wazuh-indexer" "${wazuh_version}-*"
    fi

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${indexer_installed}" ]; then
        common_logger -e "Wazuh indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer installation finished."
    fi

    eval "sysctl -q -w vm.max_map_count=262144 ${debug}"

}
function indexer_startCluster() {

    common_logger -d "Starting Wazuh indexer cluster."
    for ip_to_test in "${indexer_node_ips[@]}"; do
        eval "common_curl -XGET https://"${ip_to_test}":9200/ -k -s -o /dev/null"
        e_code="${PIPESTATUS[0]}"

        if [ "${e_code}" -eq "7" ]; then
            common_logger -e "Connectivity check failed on node ${ip_to_test} port 9200. Possible causes: Wazuh indexer not installed on the node, the Wazuh indexer service is not running or you have connectivity issues with that node. Please check this before trying again."
            exit 1
        fi
    done

    eval "wazuh_indexer_ip=( $(cat /etc/wazuh-indexer/opensearch.yml | grep network.host | sed 's/network.host:\s//') )"
    eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/wazuh-indexer/opensearch-security -icl -p 9200 -nhnv -cacert /etc/wazuh-indexer/certs/root-ca.pem -cert /etc/wazuh-indexer/certs/admin.pem -key /etc/wazuh-indexer/certs/admin-key.pem -h ${wazuh_indexer_ip} ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "The Wazuh indexer cluster security configuration could not be initialized."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer cluster security configuration initialized."
    fi

    # Validate Wazuh indexer security admin it is initialized
    indexer_security_admin_comm="common_curl -XGET https://"${indexer_node_ips[pos]}":9200/ -uadmin:admin -k --max-time 120 --silent -w \"%{http_code}\" --output /dev/null"
    http_status=$(eval "${indexer_security_admin_comm}")
    retries=0
    max_retries=5
    while [ "${http_status}" -ne 200 ]; do
        common_logger -d "Waiting for Wazuh indexer to be ready. wazuh-indexer status: ${http_status}"
        sleep 5
        retries=$((retries+1))
        if [ "${retries}" -eq "${max_retries}" ]; then
            common_logger -e "The Wazuh indexer cluster security configuration could not be initialized."
            exit 1
        fi
        http_status=$(eval "${indexer_security_admin_comm}")
    done

    # Wazuh alerts template injection
    if [ -n "${offline_install}" ]; then
        filebeat_wazuh_template="file://${offline_files_path}/wazuh-template.json"
    fi
    http_status=$(eval "common_curl --silent '${filebeat_wazuh_template}' --max-time 300 --retry 5 --retry-delay 5" | eval "common_curl -X PUT 'https://${indexer_node_ips[pos]}:9200/_template/wazuh' -H \'Content-Type: application/json\' -d @- -uadmin:admin -k --max-time 300 --silent --retry 5 --retry-delay 5 -w "%{http_code}" -o /dev/null")
    if [ -z "${http_status}" ] || [ "${http_status}" -ne 200 ]; then
        common_logger -e "The wazuh-alerts template could not be inserted into the Wazuh indexer cluster."
        exit 1
    else
        common_logger -d "Inserted wazuh-alerts template into the Wazuh indexer cluster."
    fi
}

# ------------ dashboard.sh ------------ 
function dashboard_changePort() {

    chosen_port="$1"
    http_port="${chosen_port}" 
    wazuh_dashboard_port=( "${http_port}" )
    wazuh_aio_ports=(9200 9300 1514 1515 1516 55000 "${http_port}")

    sed -i 's/server\.port: [0-9]\+$/server.port: '"${chosen_port}"'/' "$0"
    common_logger "Wazuh web interface port will be ${chosen_port}."
}
function dashboard_configure() {

    common_logger -d "Configuring Wazuh dashboard."
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig dashboard/dashboard_assistant.yml /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        dashboard_copyCertificates "${debug}"
    else
        eval "installCommon_getConfig dashboard/dashboard_assistant_distributed.yml /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        dashboard_copyCertificates "${debug}"
        if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
            pos=0
            ip=${dashboard_node_ips[0]}
        else
            for i in "${!dashboard_node_names[@]}"; do
                if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                    pos="${i}";
                fi
            done
            ip=${dashboard_node_ips[pos]}
        fi

        if [[ "${ip}" != "127.0.0.1" ]]; then
            echo "server.host: ${ip}" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
        else
            echo 'server.host: '0.0.0.0'' >> /etc/wazuh-dashboard/opensearch_dashboards.yml
        fi

        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            echo "opensearch.hosts: https://${indexer_node_ips[0]}:9200" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
        else
            echo "opensearch.hosts:" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
            for i in "${indexer_node_ips[@]}"; do
                    echo "  - https://${i}:9200" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
            done
        fi
    fi

    sed -i 's/server\.port: [0-9]\+$/server.port: '"${chosen_port}"'/' /etc/wazuh-dashboard/opensearch_dashboards.yml

    common_logger "Wazuh dashboard post-install configuration finished."

}
function dashboard_copyCertificates() {

    common_logger -d "Copying Wazuh dashboard certificates."
    eval "rm -f ${dashboard_cert_path}/* ${debug}"
    name=${dashboard_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${name}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${name}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${dashboard_cert_path} ${debug}"
        eval "sed -i s/dashboard.pem/${name}.pem/ /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        eval "sed -i s/dashboard-key.pem/${name}-key.pem/ /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/${name}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/${name}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/ ${debug}"
        eval "chmod 500 ${dashboard_cert_path} ${debug}"
        eval "chmod 400 ${dashboard_cert_path}/* ${debug}"
        eval "chown wazuh-dashboard:wazuh-dashboard ${dashboard_cert_path}/* ${debug}"
        common_logger -d "Wazuh dashboard certificate setup finished."
    else
        common_logger -e "No certificates found. Wazuh dashboard  could not be initialized."
        installCommon_rollBack
        exit 1
    fi

}
function dashboard_initialize() {

    common_logger "Initializing Wazuh dashboard web application."
    installCommon_getPass "admin"
    j=0

    if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
        nodes_dashboard_ip=${dashboard_node_ips[0]}
    else
        for i in "${!dashboard_node_names[@]}"; do
            if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                pos="${i}";
            fi
        done
        nodes_dashboard_ip=${dashboard_node_ips[pos]}
    fi

    if [ "${nodes_dashboard_ip}" == "localhost" ] || [[ "${nodes_dashboard_ip}" == 127.* ]]; then
        print_ip="<wazuh-dashboard-ip>"
    else
        print_ip="${nodes_dashboard_ip}"
    fi

    until [ "$(curl -XGET https://"${nodes_dashboard_ip}":"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)" -eq "200" ] || [ "${j}" -eq "12" ]; do
        sleep 10
        j=$((j+1))
        common_logger -d "Retrying Wazuh dashboard connection..."
    done

    if [ ${j} -lt 12 ]; then
        common_logger -d "Wazuh dashboard connection was successful."
        if [ "${#server_node_names[@]}" -eq 1 ]; then
            wazuh_api_address=${server_node_ips[0]}
        else
            for i in "${!server_node_types[@]}"; do
                if [[ "${server_node_types[i]}" == "master" ]]; then
                    wazuh_api_address=${server_node_ips[i]}
                fi
            done
        fi
        if [ -f "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml" ]; then
            eval "sed -i 's,url: https://localhost,url: https://${wazuh_api_address},g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml ${debug}"
        fi

        common_logger "Wazuh dashboard web application initialized."
        common_logger -nl "--- Summary ---"
        common_logger -nl "You can access the web interface https://${print_ip}:${http_port}\n    User: admin\n    Password: ${u_pass}"

    else
        flag="-w"
        if [ -z "${force}" ]; then
            flag="-e"
        fi
        failed_nodes=()
        common_logger "${flag}" "Cannot connect to Wazuh dashboard."

        for i in "${!indexer_node_ips[@]}"; do
            curl=$(common_curl -XGET https://"${indexer_node_ips[i]}":9200/ -uadmin:"${u_pass}" -k -s --max-time 300 --retry 5 --retry-delay 5 --fail)
            exit_code=${PIPESTATUS[0]}
            if [[ "${exit_code}" -eq "7" ]]; then
                failed_connect=1
                failed_nodes+=("${indexer_node_names[i]}")
            elif [ "${exit_code}" -eq "22" ]; then
                sec_not_initialized=1
            fi
        done
        if [ -n "${failed_connect}" ]; then
            common_logger "${flag}" "Failed to connect with ${failed_nodes[*]}. Connection refused."
        fi

        if [ -n "${sec_not_initialized}" ]; then
            common_logger "${flag}" "Wazuh indexer security settings not initialized. Please run the installation assistant using -s|--start-cluster in one of the wazuh indexer nodes."
        fi

        if [ -z "${force}" ]; then
            common_logger "If you want to install Wazuh dashboard without waiting for the Wazuh indexer cluster, use the -fd option"
            installCommon_rollBack
            exit 1
        else
            common_logger -nl "--- Summary ---"
            common_logger -nl "When Wazuh dashboard is able to connect to your Wazuh indexer cluster, you can access the web interface https://${print_ip}\n    User: admin\n    Password: ${u_pass}"
        fi
    fi

}
function dashboard_initializeAIO() {

    wazuh_api_address=${server_node_ips[0]}
    common_logger "Initializing Wazuh dashboard web application."
    installCommon_getPass "admin"
    http_code=$(curl -XGET https://localhost:"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)
    retries=0
    max_dashboard_initialize_retries=20
    while [ "${http_code}" -ne "200" ] && [ "${retries}" -lt "${max_dashboard_initialize_retries}" ]
    do
        http_code=$(curl -XGET https://localhost:"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)
        common_logger "Wazuh dashboard web application not yet initialized. Waiting..."
        retries=$((retries+1))
        sleep 15
    done
    if [ "${http_code}" -eq "200" ]; then
        if [ -f "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml" ]; then
            eval "sed -i 's,url: https://localhost,url: https://${wazuh_api_address},g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml ${debug}"
        fi
        common_logger "Wazuh dashboard web application initialized."
        common_logger -nl "--- Summary ---"
        common_logger -nl "You can access the web interface https://<wazuh-dashboard-ip>:${http_port}\n    User: admin\n    Password: ${u_pass}"
    else
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    fi
}
function dashboard_install() {

    common_logger "Starting Wazuh dashboard installation."
    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "wazuh-dashboard" "${wazuh_version}-*"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "wazuh-dashboard" "${wazuh_version}-*"
    fi
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${dashboard_installed}" ]; then
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh dashboard installation finished."
    fi

}

function dist_detect() {


DIST_NAME="Linux"
DIST_VER="0"
DIST_SUBVER="0"

if [ -r "/etc/os-release" ]; then
    . /etc/os-release
    DIST_NAME=$ID
    DIST_VER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
    if [ "X$DIST_VER" = "X" ]; then
        DIST_VER="0"
    fi
    if [ "$DIST_NAME" = "amzn" ] && [ "$DIST_VER" = "2018" ]; then
        DIST_VER="1"
    fi
    DIST_SUBVER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi

if [ ! -r "/etc/os-release" ] || [ "$DIST_NAME" = "centos" ]; then
    # CentOS
    if [ -r "/etc/centos-release" ]; then
        DIST_NAME="centos"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' /etc/centos-release`

    # RedHat
    elif [ -r "/etc/redhat-release" ]; then
        if grep -q "CentOS" /etc/redhat-release; then
            DIST_NAME="centos"
        else
            DIST_NAME="rhel"
        fi
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/redhat-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' /etc/redhat-release`

    # Ubuntu
    elif [ -r "/etc/lsb-release" ]; then
        . /etc/lsb-release
        DIST_NAME="ubuntu"
        DIST_VER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p')
        DIST_SUBVER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p')

    # Debian
    elif [ -r "/etc/debian_version" ]; then
        DIST_NAME="debian"
        DIST_VER=`sed -rn 's/[^0-9]*([0-9]+).*/\1/p' /etc/debian_version`
        DIST_SUBVER=`sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p' /etc/debian_version`

    # Amazon Linux 2, 2023
    elif [ -r "/etc/system-release" ]; then
        if grep -q "Amazon Linux release" /etc/system-release; then
            DIST_NAME="amzn"
            DIST_VER_FULL=`sed -rn 's/.*release ([0-9]+(\.[0-9]+)?).*/\1/p' /etc/system-release`
            DIST_VER=`echo $DIST_VER_FULL | cut -d. -f1`
            DIST_SUBVER=`echo $DIST_VER_FULL | cut -d. -f2`
        fi
    elif [ "X$(uname)" = "XLinux" ]; then
        DIST_NAME="Linux"

    fi
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi
}
function common_checkAptLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while fuser "${apt_lockfile}" >/dev/null 2>&1 && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using APT. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}
function common_logger() {

    now=$(date +'%d/%m/%Y %H:%M:%S')
    mtype="INFO:"
    debugLogger=
    nolog=
    if [ -n "${1}" ]; then
        while [ -n "${1}" ]; do
            case ${1} in
                "-e")
                    mtype="ERROR:"
                    shift 1
                    ;;
                "-w")
                    mtype="WARNING:"
                    shift 1
                    ;;
                "-d")
                    debugLogger=1
                    mtype="DEBUG:"
                    shift 1
                    ;;
                "-nl")
                    nolog=1
                    shift 1
                    ;;
                *)
                    message="${1}"
                    shift 1
                    ;;
            esac
        done
    fi

    if [ -z "${debugLogger}" ] || { [ -n "${debugLogger}" ] && [ -n "${debugEnabled}" ]; }; then
        if [ -z "${nolog}" ] && { [ "$EUID" -eq 0 ] || [[ "$(basename "$0")" =~ $cert_tool_script_name ]]; }; then
            printf "%s\n" "${now} ${mtype} ${message}" | tee -a ${logfile}
        else
            printf "%b\n" "${now} ${mtype} ${message}"
        fi
    fi

}
function common_checkRoot() {

    common_logger -d "Checking root permissions."
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
    fi

    common_logger -d "Checking sudo package."
    if ! command -v sudo > /dev/null; then 
        common_logger -e "The sudo package is not installed and it is necessary for the installation."
        exit 1;
    fi
}
function common_checkInstalled() {

    common_logger -d "Checking Wazuh installation."
    wazuh_installed=""
    indexer_installed=""
    filebeat_installed=""
    dashboard_installed=""

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q wazuh-manager --quiet && wazuh_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuh_installed=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    fi

    if [ -d "/var/ossec" ]; then
        common_logger -d "There are Wazuh remaining files."
        wazuh_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q wazuh-indexer --quiet && indexer_installed=1"

    elif [ "${sys_type}" == "apt-get" ]; then
        indexer_installed=$(apt list --installed 2>/dev/null | grep wazuh-indexer)
    fi

    if [ -d "/var/lib/wazuh-indexer/" ] || [ -d "/usr/share/wazuh-indexer" ] || [ -d "/etc/wazuh-indexer" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        common_logger -d "There are Wazuh indexer remaining files."
        indexer_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q filebeat --quiet && filebeat_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeat_installed=$(apt list --installed  2>/dev/null | grep filebeat)
    fi

    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        common_logger -d "There are Filebeat remaining files."
        filebeat_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q wazuh-dashboard --quiet && dashboard_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        dashboard_installed=$(apt list --installed  2>/dev/null | grep wazuh-dashboard)
    fi

    if [ -d "/var/lib/wazuh-dashboard/" ] || [ -d "/usr/share/wazuh-dashboard" ] || [ -d "/etc/wazuh-dashboard" ] || [ -d "/run/wazuh-dashboard/" ]; then
        common_logger -d "There are Wazuh dashboard remaining files."
        dashboard_remaining_files=1
    fi

}
function common_checkSystem() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="yum"
        sep="-"
        common_logger -d "YUM package manager will be used."
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="apt-get"
        sep="="
        common_logger -d "APT package manager will be used."
    else
        common_logger -e "Couldn't find YUM or APT package manager. Try installing the one corresponding to your operating system and then, launch the installation assistant again."
        exit 1
    fi

}
function common_checkWazuhConfigYaml() {

    common_logger -d "Checking Wazuh YAML configuration file."
    filecorrect=$(cert_parseYaml "${config_file}" | grep -Ev '^#|^\s*$' | grep -Pzc "\A(\s*(nodes_indexer__name|nodes_indexer__ip|nodes_server__name|nodes_server__ip|nodes_server__node_type|nodes_dashboard__name|nodes_dashboard__ip)=.*?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The configuration file ${config_file} does not have a correct format."
        exit 1
    fi

}
function common_curl() {

    if [ -n "${curl_has_connrefused}" ]; then
        eval "curl $@ --retry-connrefused"
        e_code="${PIPESTATUS[0]}"
    else
        retries=0
        eval "curl $@"
        e_code="${PIPESTATUS[0]}"
        while [ "${e_code}" -eq 7 ] && [ "${retries}" -ne 12 ]; do
            retries=$((retries+1))
            sleep 5
            eval "curl $@"
            e_code="${PIPESTATUS[0]}"
        done
    fi
    return "${e_code}"

}
function common_remove_gpg_key() {

    common_logger -d "Removing GPG key from system."
    if [ "${sys_type}" == "yum" ]; then
        if { rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' | grep "Wazuh"; } >/dev/null ; then
            key=$(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' | grep "Wazuh Signing Key" | awk '{print $1}' )
            rpm -e "${key}"
        else
            common_logger "Wazuh GPG key not found in the system"
            return 1
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        if [ -f "/usr/share/keyrings/wazuh.gpg" ]; then
            rm -rf "/usr/share/keyrings/wazuh.gpg" "${debug}"
        else
            common_logger "Wazuh GPG key not found in the system"
            return 1
        fi
    fi

}
function common_checkYumLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while [ -f "${yum_lockfile}" ] && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using YUM. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}
function cert_cleanFiles() {
    
    common_logger -d "Cleaning certificate files."
    eval "rm -f ${cert_tmp_path}/*.csr ${debug}"
    eval "rm -f ${cert_tmp_path}/*.srl ${debug}"
    eval "rm -f ${cert_tmp_path}/*.conf ${debug}"
    eval "rm -f ${cert_tmp_path}/admin-key-temp.pem ${debug}"

}
function cert_checkOpenSSL() {

    common_logger -d "Checking if OpenSSL is installed."

    if [ -z "$(command -v openssl)" ]; then
        common_logger -e "OpenSSL not installed."
        exit 1
    fi

}
function cert_checkRootCA() {

    common_logger -d "Checking if the root CA exists."

    if  [[ -n ${rootca} || -n ${rootcakey} ]]; then
        # Verify variables match keys
        if [[ ${rootca} == *".key" ]]; then
            ca_temp=${rootca}
            rootca=${rootcakey}
            rootcakey=${ca_temp}
        fi
        # Validate that files exist
        if [[ -e ${rootca} ]]; then
            eval "cp ${rootca} ${cert_tmp_path}/root-ca.pem ${debug}"
        else
            common_logger -e "The file ${rootca} does not exists"
            cert_cleanFiles
            exit 1
        fi
        if [[ -e ${rootcakey} ]]; then
            eval "cp ${rootcakey} ${cert_tmp_path}/root-ca.key ${debug}"
        else
            common_logger -e "The file ${rootcakey} does not exists"
            cert_cleanFiles
            exit 1
        fi
    else
        cert_generateRootCAcertificate
    fi

}
function cert_executeAndValidate() {

    command_output=$(eval "$@" 2>&1)
    e_code="${PIPESTATUS[0]}"

    if [ "${e_code}" -ne 0 ]; then
        common_logger -e "Error generating the certificates."
        common_logger -d "Error executing command: $@"
        common_logger -d "Error output: ${command_output}"
        cert_cleanFiles
        exit 1
    fi

}
function cert_generateAdmincertificate() {

    common_logger "Generating Admin certificates."
    common_logger -d "Generating Admin private key."
    cert_executeAndValidate "openssl genrsa -out ${cert_tmp_path}/admin-key-temp.pem 2048"
    common_logger -d "Converting Admin private key to PKCS8 format."
    cert_executeAndValidate "openssl pkcs8 -inform PEM -outform PEM -in ${cert_tmp_path}/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${cert_tmp_path}/admin-key.pem"
    common_logger -d "Generating Admin CSR."
    cert_executeAndValidate "openssl req -new -key ${cert_tmp_path}/admin-key.pem -out ${cert_tmp_path}/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Wazuh/CN=admin'"
    common_logger -d "Creating Admin certificate."
    cert_executeAndValidate "openssl x509 -days 3650 -req -in ${cert_tmp_path}/admin.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -sha256 -out ${cert_tmp_path}/admin.pem"

}
function cert_generateCertificateconfiguration() {

    common_logger -d "Generating certificate configuration."
    cat > "${cert_tmp_path}/${1}.conf" <<- EOF
        [ req ]
        prompt = no
        default_bits = 2048
        default_md = sha256
        distinguished_name = req_distinguished_name
        x509_extensions = v3_req

        [req_distinguished_name]
        C = US
        L = California
        O = Wazuh
        OU = Wazuh
        CN = cname

        [ v3_req ]
        authorityKeyIdentifier=keyid,issuer
        basicConstraints = CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names

        [alt_names]
        IP.1 = cip
	EOF


    conf="$(awk '{sub("CN = cname", "CN = '"${1}"'")}1' "${cert_tmp_path}/${1}.conf")"
    echo "${conf}" > "${cert_tmp_path}/${1}.conf"

    if [ "${#@}" -gt 1 ]; then
        sed -i '/IP.1/d' "${cert_tmp_path}/${1}.conf"
        for (( i=2; i<=${#@}; i++ )); do
            isIP=$(echo "${!i}" | grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
            isDNS=$(echo "${!i}" | grep -P "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\.([A-Za-z]{2,})$" )            j=$((i-1))
            if [ "${isIP}" ]; then
                printf '%s\n' "        IP.${j} = ${!i}" >> "${cert_tmp_path}/${1}.conf"
            elif [ "${isDNS}" ]; then
                printf '%s\n' "        DNS.${j} = ${!i}" >> "${cert_tmp_path}/${1}.conf"
            else
                common_logger -e "Invalid IP or DNS ${!i}"
                exit 1
            fi
        done
    else
        common_logger -e "No IP or DNS specified"
        exit 1
    fi

}
function cert_generateIndexercertificates() {

    if [ ${#indexer_node_names[@]} -gt 0 ]; then
        common_logger "Generating Wazuh indexer certificates."

        for i in "${!indexer_node_names[@]}"; do
            indexer_node_name=${indexer_node_names[$i]}
            common_logger -d "Creating the certificates for ${indexer_node_name} indexer node."
            cert_generateCertificateconfiguration "${indexer_node_name}" "${indexer_node_ips[i]}"
            common_logger -d "Creating the Wazuh indexer tmp key pair."
            cert_executeAndValidate "openssl req -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/${indexer_node_name}-key.pem -out ${cert_tmp_path}/${indexer_node_name}.csr -config ${cert_tmp_path}/${indexer_node_name}.conf"
            common_logger -d "Creating the Wazuh indexer certificates."
            cert_executeAndValidate "openssl x509 -req -in ${cert_tmp_path}/${indexer_node_name}.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -out ${cert_tmp_path}/${indexer_node_name}.pem -extfile ${cert_tmp_path}/${indexer_node_name}.conf -extensions v3_req -days 3650"
        done
    else
        return 1
    fi

}
function cert_generateFilebeatcertificates() {

    if [ ${#server_node_names[@]} -gt 0 ]; then
        common_logger "Generating Filebeat certificates."

        for i in "${!server_node_names[@]}"; do
            server_name="${server_node_names[i]}"
            common_logger -d "Generating the certificates for ${server_name} server node."
            j=$((i+1))
            declare -a server_ips=(server_node_ip_"$j"[@])
            cert_generateCertificateconfiguration "${server_name}" "${!server_ips}"
            common_logger -d "Creating the Wazuh server tmp key pair."
            cert_executeAndValidate "openssl req -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/${server_name}-key.pem -out ${cert_tmp_path}/${server_name}.csr  -config ${cert_tmp_path}/${server_name}.conf"
            common_logger -d "Creating the Wazuh server certificates."
            cert_executeAndValidate "openssl x509 -req -in ${cert_tmp_path}/${server_name}.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -out ${cert_tmp_path}/${server_name}.pem -extfile ${cert_tmp_path}/${server_name}.conf -extensions v3_req -days 3650"
        done
    else
        return 1
    fi

}
function cert_generateDashboardcertificates() {
    if [ ${#dashboard_node_names[@]} -gt 0 ]; then
        common_logger "Generating Wazuh dashboard certificates."

        for i in "${!dashboard_node_names[@]}"; do
            dashboard_node_name="${dashboard_node_names[i]}"
            cert_generateCertificateconfiguration "${dashboard_node_name}" "${dashboard_node_ips[i]}"
            common_logger -d "Creating the Wazuh dashboard tmp key pair."
            cert_executeAndValidate "openssl req -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/${dashboard_node_name}-key.pem -out ${cert_tmp_path}/${dashboard_node_name}.csr -config ${cert_tmp_path}/${dashboard_node_name}.conf"
            common_logger -d "Creating the Wazuh dashboard certificates."
            cert_executeAndValidate "openssl x509 -req -in ${cert_tmp_path}/${dashboard_node_name}.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -out ${cert_tmp_path}/${dashboard_node_name}.pem -extfile ${cert_tmp_path}/${dashboard_node_name}.conf -extensions v3_req -days 3650"
        done
    else
        return 1
    fi

}
function cert_generateRootCAcertificate() {

    common_logger "Generating the root certificate."
    cert_executeAndValidate "openssl req -x509 -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/root-ca.key -out ${cert_tmp_path}/root-ca.pem -batch -subj '/OU=Wazuh/O=Wazuh/L=California/' -days 3650"

}
function cert_parseYaml() {

    local prefix=$2
    local separator=${3:-_}
    local indexfix
    # Detect awk flavor
    if awk --version 2>&1 | grep -q "GNU Awk" ; then
    # GNU Awk detected
    indexfix=-1
    elif awk -Wv 2>&1 | grep -q "mawk" ; then
    # mawk detected
    indexfix=0
    fi

    local s='[[:space:]]*' sm='[ \t]*' w='[a-zA-Z0-9_]*' fs=${fs:-$(echo @|tr @ '\034')} i=${i:-  }
    cat $1 2>/dev/null | \
    awk -F$fs "{multi=0; 
        if(match(\$0,/$sm\|$sm$/)){multi=1; sub(/$sm\|$sm$/,\"\");}
        if(match(\$0,/$sm>$sm$/)){multi=2; sub(/$sm>$sm$/,\"\");}
        while(multi>0){
            str=\$0; gsub(/^$sm/,\"\", str);
            indent=index(\$0,str);
            indentstr=substr(\$0, 0, indent+$indexfix) \"$i\";
            obuf=\$0;
            getline;
            while(index(\$0,indentstr)){
                obuf=obuf substr(\$0, length(indentstr)+1);
                if (multi==1){obuf=obuf \"\\\\n\";}
                if (multi==2){
                    if(match(\$0,/^$sm$/))
                        obuf=obuf \"\\\\n\";
                        else obuf=obuf \" \";
                }
                getline;
            }
            sub(/$sm$/,\"\",obuf);
            print obuf;
            multi=0;
            if(match(\$0,/$sm\|$sm$/)){multi=1; sub(/$sm\|$sm$/,\"\");}
            if(match(\$0,/$sm>$sm$/)){multi=2; sub(/$sm>$sm$/,\"\");}
        }
    print}" | \
    sed  -e "s|^\($s\)?|\1-|" \
        -ne "s|^$s#.*||;s|$s#[^\"']*$||;s|^\([^\"'#]*\)#.*|\1|;t1;t;:1;s|^$s\$||;t2;p;:2;d" | \
    sed -ne "s|,$s\]$s\$|]|" \
        -e ":1;s|^\($s\)\($w\)$s:$s\(&$w\)\?$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1\2: \3[\4]\n\1$i- \5|;t1" \
        -e "s|^\($s\)\($w\)$s:$s\(&$w\)\?$s\[$s\(.*\)$s\]|\1\2: \3\n\1$i- \4|;" \
        -e ":2;s|^\($s\)-$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1- [\2]\n\1$i- \3|;t2" \
        -e "s|^\($s\)-$s\[$s\(.*\)$s\]|\1-\n\1$i- \2|;p" | \
    sed -ne "s|,$s}$s\$|}|" \
        -e ":1;s|^\($s\)-$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1- {\2}\n\1$i\3: \4|;t1" \
        -e "s|^\($s\)-$s{$s\(.*\)$s}|\1-\n\1$i\2|;" \
        -e ":2;s|^\($s\)\($w\)$s:$s\(&$w\)\?$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1\2: \3 {\4}\n\1$i\5: \6|;t2" \
        -e "s|^\($s\)\($w\)$s:$s\(&$w\)\?$s{$s\(.*\)$s}|\1\2: \3\n\1$i\4|;p" | \
    sed  -e "s|^\($s\)\($w\)$s:$s\(&$w\)\(.*\)|\1\2:\4\n\3|" \
        -e "s|^\($s\)-$s\(&$w\)\(.*\)|\1- \3\n\2|" | \
    sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\(---\)\($s\)||" \
        -e "s|^\($s\)\(\.\.\.\)\($s\)||" \
        -e "s|^\($s\)-$s[\"']\(.*\)[\"']$s\$|\1$fs$fs\2|p;t" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p;t" \
        -e "s|^\($s\)-$s\(.*\)$s\$|\1$fs$fs\2|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\?\(.*\)$s\$|\1$fs\2$fs\3|" \
        -e "s|^\($s\)[\"']\?\([^&][^$fs]\+\)[\"']$s\$|\1$fs$fs$fs\2|" \
        -e "s|^\($s\)[\"']\?\([^&][^$fs]\+\)$s\$|\1$fs$fs$fs\2|" \
        -e "s|$s\$||p" | \
    awk -F$fs "{
        gsub(/\t/,\"        \",\$1);
        gsub(\"name: \", \"\");
        if(NF>3){if(value!=\"\"){value = value \" \";}value = value  \$4;}
        else {
        if(match(\$1,/^&/)){anchor[substr(\$1,2)]=full_vn;getline};
        indent = length(\$1)/length(\"$i\");
        vname[indent] = \$2;
        value= \$3;
        for (i in vname) {if (i > indent) {delete vname[i]; idx[i]=0}}
        if(length(\$2)== 0){  vname[indent]= ++idx[indent] };
        vn=\"\"; for (i=0; i<indent; i++) { vn=(vn)(vname[i])(\"$separator\")}
        vn=\"$prefix\" vn;
        full_vn=vn vname[indent];
        if(vn==\"$prefix\")vn=\"$prefix$separator\";
        if(vn==\"_\")vn=\"__\";
        }
        assignment[full_vn]=value;
        if(!match(assignment[vn], full_vn))assignment[vn]=assignment[vn] \" \" full_vn;
        if(match(value,/^\*/)){
            ref=anchor[substr(value,2)];
            if(length(ref)==0){
            printf(\"%s=\\\"%s\\\"\n\", full_vn, value);
            } else {
            for(val in assignment){
                if((length(ref)>0)&&index(val, ref)==1){
                    tmpval=assignment[val];
                    sub(ref,full_vn,val);
                if(match(val,\"$separator\$\")){
                    gsub(ref,full_vn,tmpval);
                } else if (length(tmpval) > 0) {
                    printf(\"%s=\\\"%s\\\"\n\", val, tmpval);
                }
                assignment[val]=tmpval;
                }
            }
        }
    } else if (length(value) > 0) {
        printf(\"%s=\\\"%s\\\"\n\", full_vn, value);
    }
    }END{
        for(val in assignment){
            if(match(val,\"$separator\$\"))
                printf(\"%s=\\\"%s\\\"\n\", val, assignment[val]);
        }
    }"

}
function cert_checkPrivateIp() {
    
    local ip=$1
    common_logger -d "Checking if ${ip} is private."

    # Check private IPv4 ranges
    if [[ $ip =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^(127\.) ]]; then
        return 0
    fi

    # Check private IPv6 ranges (fc00::/7 prefix)
    if [[ $ip =~ ^fc ]]; then
        return 0
    fi

    return 1

}
function cert_readConfig() {

    common_logger -d "Reading configuration file."

    if [ -f "${config_file}" ]; then
        if [ ! -s "${config_file}" ]; then
            common_logger -e "File ${config_file} is empty"
            exit 1
        fi
        eval "$(cert_convertCRLFtoLF "${config_file}")"

        eval "indexer_node_names=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+=" | cut -d = -f 2 ) )"
        eval "server_node_names=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+server[_]+[0-9]+=" | cut -d = -f 2 ) )"
        eval "dashboard_node_names=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+[0-9]+=" | cut -d = -f 2) )"
        eval "indexer_node_ips=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+[_]+ip=" | cut -d = -f 2) )"
        eval "server_node_ips=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+server[_]+[0-9]+[_]+ip=" | cut -d = -f 2) )"
        eval "dashboard_node_ips=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+dashboard[_]+[0-9]+[_]+ip=" | cut -d = -f 2 ) )"
        eval "server_node_types=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+server[_]+[0-9]+[_]+node_type=" | cut -d = -f 2 ) )"
        eval "number_server_ips=( $(cert_parseYaml "${config_file}" | grep -o -E 'nodes[_]+server[_]+[0-9]+[_]+ip' | sort -u | wc -l) )"
        all_ips=("${indexer_node_ips[@]}" "${server_node_ips[@]}" "${dashboard_node_ips[@]}")

        for ip in "${all_ips[@]}"; do
            isIP=$(echo "${ip}" | grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
            if [[ -n "${isIP}" ]]; then
                if ! cert_checkPrivateIp "$ip"; then
                    common_logger -e "The IP ${ip} is public."
                    exit 1
                fi
            fi
        done

        for i in $(seq 1 "${number_server_ips}"); do
            nodes_server="nodes[_]+server[_]+${i}[_]+ip"
            eval "server_node_ip_$i=( $( cert_parseYaml "${config_file}" | grep -E "${nodes_server}" | sed '/\./!d' | cut -d = -f 2 | sed -r 's/\s+//g') )"
        done

        unique_names=($(echo "${indexer_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_names[@]}" -ne "${#indexer_node_names[@]}" ]; then 
            common_logger -e "Duplicated indexer node names."
            exit 1
        fi

        unique_ips=($(echo "${indexer_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_ips[@]}" -ne "${#indexer_node_ips[@]}" ]; then 
            common_logger -e "Duplicated indexer node ips."
            exit 1
        fi

        unique_names=($(echo "${server_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_names[@]}" -ne "${#server_node_names[@]}" ]; then 
            common_logger -e "Duplicated Wazuh server node names."
            exit 1
        fi

        unique_ips=($(echo "${server_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_ips[@]}" -ne "${#server_node_ips[@]}" ]; then 
            common_logger -e "Duplicated Wazuh server node ips."
            exit 1
        fi

        unique_names=($(echo "${dashboard_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_names[@]}" -ne "${#dashboard_node_names[@]}" ]; then
            common_logger -e "Duplicated dashboard node names."
            exit 1
        fi

        unique_ips=($(echo "${dashboard_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_ips[@]}" -ne "${#dashboard_node_ips[@]}" ]; then
            common_logger -e "Duplicated dashboard node ips."
            exit 1
        fi

        for i in "${server_node_types[@]}"; do
            if ! echo "$i" | grep -ioq master && ! echo "$i" | grep -ioq worker; then
                common_logger -e "Incorrect node_type $i must be master or worker"
                exit 1
            fi
        done

        if [ "${#server_node_names[@]}" -le 1 ]; then
            if [ "${#server_node_types[@]}" -ne 0 ]; then
                common_logger -e "The tag node_type can only be used with more than one Wazuh server."
                exit 1
            fi
        elif [ "${#server_node_names[@]}" -gt "${#server_node_types[@]}" ]; then
            common_logger -e "The tag node_type needs to be specified for all Wazuh server nodes."
            exit 1
        elif [ "${#server_node_names[@]}" -lt "${#server_node_types[@]}" ]; then
            common_logger -e "Found extra node_type tags."
            exit 1
        elif [ "$(grep -io master <<< "${server_node_types[*]}" | wc -l)" -ne 1 ]; then
            common_logger -e "Wazuh cluster needs a single master node."
            exit 1
        elif [ "$(grep -io worker <<< "${server_node_types[*]}" | wc -l)" -ne $(( ${#server_node_types[@]} - 1 )) ]; then
            common_logger -e "Incorrect number of workers."
            exit 1
        fi

        if [ "${#dashboard_node_names[@]}" -ne "${#dashboard_node_ips[@]}" ]; then
            common_logger -e "Different number of dashboard node names and IPs."
            exit 1
        fi

    else
        common_logger -e "No configuration file found."
        exit 1
    fi

}
function cert_setpermisions() {
    eval "chmod -R 744 ${cert_tmp_path} ${debug}"
}
function cert_convertCRLFtoLF() {
    if [[ ! -d "/tmp/wazuh-install-files" ]]; then
        eval "mkdir /tmp/wazuh-install-files ${debug}"
    fi
    eval "chmod -R 755 /tmp/wazuh-install-files ${debug}"
    eval "tr -d '\015' < $1 > /tmp/wazuh-install-files/new_config.yml"
    eval "mv /tmp/wazuh-install-files/new_config.yml $1 ${debug}"
}
function passwords_changePassword() {

    if [ -n "${changeall}" ]; then
        if [ -n "${indexer_installed}" ] && [ -z ${no_indexer_backup} ]; then
            eval "mkdir /etc/wazuh-indexer/backup/ ${debug}"
            eval "cp /etc/wazuh-indexer/opensearch-security/* /etc/wazuh-indexer/backup/ ${debug}"
            passwords_createBackUp
        fi
        for i in "${!passwords[@]}"
        do
            if [ -n "${indexer_installed}" ] && [ -f "/etc/wazuh-indexer/backup/internal_users.yml" ]; then
                awk -v new='"'"${hashes[i]}"'"' 'prev=="'${users[i]}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /etc/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /etc/wazuh-indexer/backup/internal_users.yml
            fi

            if [ "${users[i]}" == "admin" ]; then
                adminpass=${passwords[i]}
            elif [ "${users[i]}" == "kibanaserver" ]; then
                dashpass=${passwords[i]}
            fi

        done
    else
        if [ -z "${api}" ] && [ -n "${indexer_installed}" ]; then
            eval "mkdir /etc/wazuh-indexer/backup/ ${debug}"
            eval "cp /etc/wazuh-indexer/opensearch-security/* /etc/wazuh-indexer/backup/ ${debug}"
            passwords_createBackUp
        fi
        if [ -n "${indexer_installed}" ] && [ -f "/etc/wazuh-indexer/backup/internal_users.yml" ]; then
            awk -v new='"'"${hash}"'"' 'prev=="'${nuser}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /etc/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /etc/wazuh-indexer/backup/internal_users.yml
        fi

        if [ "${nuser}" == "admin" ]; then
            adminpass=${password}
        elif [ "${nuser}" == "kibanaserver" ]; then
            dashpass=${password}
        fi

    fi

    if [ "${nuser}" == "admin" ] || [ -n "${changeall}" ]; then
        if [ -n "${filebeat_installed}" ] && [ -z "${dashboard}" ]; then
            file_username=$(grep "username:" /etc/filebeat/filebeat.yml | awk '{print $2}')
            file_password=$(grep "password:" /etc/filebeat/filebeat.yml | awk '{print $2}')
            if [ "$file_username" != "\${username}" ] || [ "$file_password" != "\${password}" ]; then
                common_logger -w "The user and password configured in the filebeat.yml file will be updated and stored in Filebeat Keystore."
            fi
            eval "echo ${adminpass} | filebeat keystore add password --force --stdin ${debug}"
            conf="$(awk '{sub("password: .*", "password: ${password}")}1' /etc/filebeat/filebeat.yml)"
            echo "${conf}" > /etc/filebeat/filebeat.yml
            eval "echo admin | filebeat keystore add username --force --stdin ${debug}"
            conf="$(awk '{sub("username: .*", "username: ${username}")}1' /etc/filebeat/filebeat.yml)"
            echo "${conf}" > /etc/filebeat/filebeat.yml
            common_logger "The filebeat.yml file has been updated to use the Filebeat Keystore username and password."
            passwords_restartService "filebeat"
            eval "/var/ossec/bin/wazuh-keystore -f indexer -k password -v ${adminpass}"
            passwords_restartService "wazuh-manager"
        fi
    fi

    if [ "$nuser" == "kibanaserver" ] || [ -n "$changeall" ]; then
        if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
            if /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root list | grep -q opensearch.password; then
                eval "echo ${dashpass} | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password ${debug_pass} > /dev/null 2>&1"
            else
                wazuhdashold=$(grep "password:" /etc/wazuh-dashboard/opensearch_dashboards.yml )
                rk="opensearch.password: "
                wazuhdashold="${wazuhdashold//$rk}"
                conf="$(awk '{sub("opensearch.password: .*", "opensearch.password: '"${dashpass}"'")}1' /etc/wazuh-dashboard/opensearch_dashboards.yml)"
                echo "${conf}" > /etc/wazuh-dashboard/opensearch_dashboards.yml
            fi
            passwords_restartService "wazuh-dashboard"
        fi
    fi

}
function passwords_changePasswordApi() {
    #Change API password tool
    if [ -n "${changeall}" ]; then
        for i in "${!api_passwords[@]}"; do
            if [ -n "${wazuh_installed}" ]; then
                passwords_getApiUserId "${api_users[i]}"
                WAZUH_PASS_API='{\"password\":\"'"${api_passwords[i]}"'\"}'
                eval 'common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail'
                if [ "${api_users[i]}" == "${adminUser}" ]; then
                    sleep 1
                    adminPassword="${api_passwords[i]}"
                    passwords_getApiToken
                fi
                if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
                    common_logger -nl $"The password for Wazuh API user ${api_users[i]} is ${api_passwords[i]}"
                fi
            fi
            if [ "${api_users[i]}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
                passwords_changeDashboardApiPassword "${api_passwords[i]}"
            fi
        done
    else
        if [ -n "${wazuh_installed}" ]; then
            passwords_getApiUserId "${nuser}"
            WAZUH_PASS_API='{\"password\":\"'"${password}"'\"}'
            eval 'common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail'
            if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
                common_logger -nl $"The password for Wazuh API user ${nuser} is ${password}"
            fi
        fi
        if [ "${nuser}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
                passwords_changeDashboardApiPassword "${password}"
        fi
    fi
}
function passwords_changeDashboardApiPassword() {

    j=0
    until [ -n "${file_exists}" ] || [ "${j}" -eq "12" ]; do
        if [ -f "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml" ]; then
            eval "sed -i 's|password: .*|password: \"${1}\"|g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml ${debug}"
            if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
                common_logger "Updated wazuh-wui user password in wazuh dashboard. Remember to restart the service."
            fi
            file_exists=1
        fi
        sleep 5
        j=$((j+1))
    done

}
function passwords_checkUser() {

    if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
        for i in "${!api_users[@]}"; do
            if [ "${api_users[i]}" == "${nuser}" ]; then
                exists=1
            fi
        done
    else
        for i in "${!users[@]}"; do
            if [ "${users[i]}" == "${nuser}" ]; then
                exists=1
            fi
        done
    fi

    if [ -z "${exists}" ]; then
        common_logger -e "The given user does not exist"
        exit 1;
    fi

}
function passwords_checkPassword() {

    if ! echo "$1" | grep -q "[A-Z]" || ! echo "$1" | grep -q "[a-z]" || ! echo "$1" | grep -q "[0-9]" || ! echo "$1" | grep -q "[.*+?-]" || [ "${#1}" -lt 8 ] || [ "${#1}" -gt 64 ]; then
        common_logger -e "The password must have a length between 8 and 64 characters and contain at least one upper and lower case letter, a number and a symbol(.*+?-)."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
        fi
        exit 1
    fi

}
function passwords_createBackUp() {

    if [ -z "${indexer_installed}" ] && [ -z "${dashboard_installed}" ] && [ -z "${filebeat_installed}" ]; then
        common_logger -e "Cannot find Wazuh indexer, Wazuh dashboard or Filebeat on the system."
        exit 1;
    else
        if [ -n "${indexer_installed}" ]; then
            capem=$(grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml )
            rcapem="plugins.security.ssl.transport.pemtrustedcas_filepath: "
            capem="${capem//$rcapem}"
        fi
    fi

    common_logger -d "Creating password backup."
    if [ ! -d "/etc/wazuh-indexer/backup" ]; then
        eval "mkdir /etc/wazuh-indexer/backup ${debug}"
    fi
    eval "JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -backup /etc/wazuh-indexer/backup -icl -p 9200 -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -h ${IP} ${debug}"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        common_logger -e "The backup could not be created"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1;
    fi
    common_logger -d "Password backup created in /etc/wazuh-indexer/backup."

}
function passwords_generateHash() {

    if [ -n "${changeall}" ]; then
        common_logger -d "Generating password hashes."
        for i in "${!passwords[@]}"
        do
            nhash=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${passwords[i]}" 2>&1)
            if [  "${PIPESTATUS[0]}" != 0  ]; then
                common_logger -e "Hash generation failed."
                if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                    installCommon_rollBack
                fi
                exit 1;
            fi
            hashes+=("${nhash}")
        done
        common_logger -d "Password hashes generated."
    else
        common_logger "Generating password hash"
        hash=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${password}" 2>&1)
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "Hash generation failed."
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        fi
        common_logger -d "Password hash generated."
    fi

}
function passwords_generatePassword() {

    if [ -n "${nuser}" ]; then
        common_logger -d "Generating random password."
        pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
        special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
        minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
        mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
        number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
        password="$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "The password could not been generated."
            exit 1;
        fi
    else
        common_logger -d "Generating random passwords."
        for i in "${!users[@]}"; do
            pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
            special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
            minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
            mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
            number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
            passwords+=("$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')")
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "The password could not been generated."
                exit 1;
            fi
        done
        for i in "${!api_users[@]}"; do
            pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
            special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
            minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
            mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
            number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
            api_passwords+=("$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')")
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "The password could not been generated."
                exit 1;
            fi
        done
    fi
}
function passwords_generatePasswordFile() {

    common_logger -d "Generating password file."
    users=( admin anomalyadmin kibanaserver kibanaro logstash readall snapshotrestore )
    api_users=( wazuh wazuh-wui )
    user_description=(
        "Admin user for the web user interface and Wazuh indexer. Use this user to log in to Wazuh dashboard"
        "Anomaly detection user for the web user interface"
        "Wazuh dashboard user for establishing the connection with Wazuh indexer"
        "Regular Dashboard user, only has read permissions to all indices and all permissions on the .kibana index"
        "Filebeat user for CRUD operations on Wazuh indices"
        "User with READ access to all indices"
        "User with permissions to perform snapshot and restore operations"
        "Admin user used to communicate with Wazuh API"
        "Regular user to query Wazuh API"
    )
    api_user_description=(
        "Password for wazuh API user"
        "Password for wazuh-wui API user"
    )
    passwords_generatePassword

    for i in "${!users[@]}"; do
        {
        echo "# ${user_description[${i}]}"
        echo "  indexer_username: '${users[${i}]}'"
        echo "  indexer_password: '${passwords[${i}]}'"
        echo ""
        } >> "${gen_file}"
    done

    for i in "${!api_users[@]}"; do
        {
        echo "# ${api_user_description[${i}]}"
        echo "  api_username: '${api_users[${i}]}'"
        echo "  api_password: '${api_passwords[${i}]}'"
        echo ""
        } >> "${gen_file}"
    done

}
function passwords_getApiToken() {
    retries=0
    max_internal_error_retries=20

    TOKEN_API=$(curl -s -u "${adminUser}":"${adminPassword}" -k -X POST "https://localhost:55000/security/user/authenticate?raw=true" --max-time 300 --retry 5 --retry-delay 5)
    while [[ "${TOKEN_API}" =~ "Wazuh Internal Error" ]] && [ "${retries}" -lt "${max_internal_error_retries}" ]
    do
        common_logger "There was an error accessing the API. Retrying..."
        TOKEN_API=$(curl -s -u "${adminUser}":"${adminPassword}" -k -X POST "https://localhost:55000/security/user/authenticate?raw=true" --max-time 300 --retry 5 --retry-delay 5)
        retries=$((retries+1))
        sleep 10
    done
    if [[ ${TOKEN_API} =~ "Wazuh Internal Error" ]]; then
        common_logger -e "There was an error while trying to get the API token."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1
    elif [[ ${TOKEN_API} =~ "Invalid credentials" ]]; then
        common_logger -e "Invalid admin user credentials"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1
    fi

}
function passwords_getApiUsers() {

    mapfile -t api_users < <(common_curl -s -k -X GET -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\"  \"https://localhost:55000/security/users?pretty=true\" --max-time 300 --retry 5 --retry-delay 5 | grep username | awk -F': ' '{print $2}' | sed -e "s/[\'\",]//g")

}
function passwords_getApiIds() {

    mapfile -t api_ids < <(common_curl -s -k -X GET -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\"  \"https://localhost:55000/security/users?pretty=true\" --max-time 300 --retry 5 --retry-delay 5 | grep id | awk -F': ' '{print $2}' | sed -e "s/[\'\",]//g")

}
function passwords_getApiUserId() {

    user_id="noid"
    for u in "${!api_users[@]}"; do
        if [ "${1}" == "${api_users[u]}" ]; then
            user_id="${api_ids[u]}"
        fi
    done

    if [ "${user_id}" == "noid" ]; then
        common_logger -e "User ${1} is not registered in Wazuh API"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
        fi
        exit 1
    fi

}
function passwords_getNetworkHost() {

    IP=$(grep -hr "^network.host:" /etc/wazuh-indexer/opensearch.yml)
    NH="network.host: "
    IP="${IP//$NH}"

    # Remove surrounding double quotes if present
    IP="${IP//\"}"

    #allow to find ip with an interface
    if [[ ${IP} =~ _.*_ ]]; then
        interface="${IP//_}"
        IP=$(ip -o -4 addr list "${interface}" | awk '{print $4}' | cut -d/ -f1)
    fi

    if [ "${IP}" == "0.0.0.0" ]; then
        IP="localhost"
    fi
}
function passwords_readFileUsers() {

    filecorrect=$(grep -Ev '^#|^\s*$' "${p_file}" | grep -Pzc "\A(\s*(indexer_username|api_username|indexer_password|api_password):[ \t]+[\'\"]?[\w.*+?-]+[\'\"]?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The password file does not have a correct format or password uses invalid characters. Allowed characters: A-Za-z0-9.*+?

For Wazuh indexer users, the file must have this format:

# Description
  indexer_username: <user>
  indexer_password: <password>

For Wazuh API users, the file must have this format:

# Description
  api_username: <user>
  api_password: <password>

"
        exit 1
    fi

    sfileusers=$(grep indexer_username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")
    sfilepasswords=$(grep indexer_password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")

    sfileapiusers=$(grep api_username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")
    sfileapipasswords=$(grep api_password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")

    mapfile -t fileusers <<< "${sfileusers}"
    mapfile -t filepasswords <<< "${sfilepasswords}"

    mapfile -t fileapiusers <<< "${sfileapiusers}"
    mapfile -t fileapipasswords <<< "${sfileapipasswords}"

    if [ -n "${changeall}" ]; then
        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    passwords_checkPassword "${filepasswords[j]}"
                    passwords[i]=${filepasswords[j]}
                    supported=true
                fi
            done
            if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The user ${fileusers[j]} does not exist"
            fi
        done

        if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
            for j in "${!fileapiusers[@]}"; do
                supported=false
                for i in "${!api_users[@]}"; do
                    if [[ "${api_users[i]}" == "${fileapiusers[j]}" ]]; then
                        passwords_checkPassword "${fileapipasswords[j]}"
                        api_passwords[i]=${fileapipasswords[j]}
                        supported=true
                    fi
                done
                if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                    common_logger -e "The Wazuh API user ${fileapiusers[j]} does not exist"
                fi
            done
        fi
    else
        finalusers=()
        finalpasswords=()

        finalapiusers=()
        finalapipasswords=()

        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    passwords_checkPassword "${filepasswords[j]}"
                    finalusers+=("${fileusers[j]}")
                    finalpasswords+=("${filepasswords[j]}")
                    supported=true
                fi
            done
            if [ ${supported} = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The user ${fileusers[j]} does not exist"
            fi
        done

        if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
            for j in "${!fileapiusers[@]}"; do
                supported=false
                for i in "${!api_users[@]}"; do
                    if [[ "${api_users[i]}" == "${fileapiusers[j]}" ]]; then
                        passwords_checkPassword "${fileapipasswords[j]}"
                        finalapiusers+=("${fileapiusers[j]}")
                        finalapipasswords+=("${fileapipasswords[j]}")
                        supported=true
                    fi
                done
                if [ ${supported} = false ] && [ -n "${indexer_installed}" ]; then
                    common_logger -e "The Wazuh API user ${fileapiusers[j]} does not exist"
                fi
            done
        fi

        users=()
        passwords=()
        mapfile -t users < <(printf "%s\n" "${finalusers[@]}")
        mapfile -t passwords < <(printf "%s\n" "${finalpasswords[@]}")
        mapfile -t api_users < <(printf "%s\n" "${finalapiusers[@]}")
        mapfile -t api_passwords < <(printf "%s\n" "${finalapipasswords[@]}")

        changeall=1
    fi

}
function passwords_readUsers() {

    passwords_updateInternalUsers
    susers=$(grep -B 1 hash: /etc/wazuh-indexer/opensearch-security/internal_users.yml | grep -v hash: | grep -v "-" | awk '{ print substr( $0, 1, length($0)-1 ) }')
    mapfile -t users <<< "${susers[@]}"

}
function passwords_restartService() {

    common_logger -d "Restarting ${1} service..."
    if [ "$#" -ne 1 ]; then
        common_logger -e "passwords_restartService must be called with 1 argument."
        exit 1
    fi

    if [[ -d /run/systemd/system ]]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl restart ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started."
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        eval "/etc/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started."
        fi
    else
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        common_logger -e "${1} could not start. No service manager found on the system."
        exit 1;
    fi

}
function passwords_runSecurityAdmin() {

    common_logger -d "Running security admin tool."
    if [ -z "${indexer_installed}" ] && [ -z "${dashboard_installed}" ] && [ -z "${filebeat_installed}" ]; then
        common_logger -e "Cannot find Wazuh indexer, Wazuh dashboard or Filebeat on the system."
        exit 1;
    else
        if [ -n "${indexer_installed}" ]; then
            capem=$(grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml )
            rcapem="plugins.security.ssl.transport.pemtrustedcas_filepath: "
            capem="${capem//$rcapem}"
        fi
    fi

    common_logger -d "Loading new passwords changes."
    eval "OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/backup/internal_users.yml -t internalusers -p 9200 -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -icl -h ${IP} ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "Could not load the changes."
        exit 1;
    fi
    eval "cp /etc/wazuh-indexer/backup/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml"
    eval "rm -rf /etc/wazuh-indexer/backup/ ${debug}"

    if [[ -n "${nuser}" ]] && [[ -n ${autopass} ]]; then
        common_logger -nl "The password for user ${nuser} is ${password}"
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard, Wazuh server, and Filebeat nodes if necessary, and restart the services."
    fi

    if [[ -n "${nuser}" ]] && [[ -z ${autopass} ]]; then
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard, Wazuh server, and Filebeat nodes if necessary, and restart the services."
    fi

    if [ -n "${changeall}" ]; then
        if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
            for i in "${!users[@]}"; do
                common_logger -nl "The password for user ${users[i]} is ${passwords[i]}"
            done
            common_logger -w "Wazuh indexer passwords changed. Remember to update the password in the Wazuh dashboard, Wazuh server, and Filebeat nodes if necessary, and restart the services."
        else
            common_logger -d "Passwords changed."
        fi
    fi

}
function passwords_updateInternalUsers() {

    common_logger "Updating the internal users."
    backup_datetime=$(date +"%Y%m%d_%H%M%S")
    internal_users_backup_path="/etc/wazuh-indexer/internalusers-backup"
    passwords_getNetworkHost
    passwords_createBackUp

    eval "mkdir -p ${internal_users_backup_path} ${debug}"
    eval "cp /etc/wazuh-indexer/backup/internal_users.yml ${internal_users_backup_path}/internal_users_${backup_datetime}.yml.bkp ${debug}"
    eval "chmod 750 ${internal_users_backup_path} ${debug}"
    eval "chmod 640 ${internal_users_backup_path}/internal_users_${backup_datetime}.yml.bkp"
    eval "chown -R wazuh-indexer:wazuh-indexer ${internal_users_backup_path} ${debug}"
    common_logger "A backup of the internal users has been saved in the /etc/wazuh-indexer/internalusers-backup folder."

    eval "cp /etc/wazuh-indexer/backup/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml ${debug}"
    eval "rm -rf /etc/wazuh-indexer/backup/ ${debug}"
    common_logger -d "The internal users have been updated before changing the passwords."

}

main "$@"

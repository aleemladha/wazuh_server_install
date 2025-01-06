# Ansible Role to Install Wazuh SIEM Unified XDR and SIEM protection with SOC Fortress Rules

## Why use Wazuh with SocFortress Rules: <a href="https://socfortress.medium.com/">SocFortress Blog</a>

The objective for this repo is to provide the Wazuh community with rulesets that are more accurate, descriptive, and enriched from various sources and integrations.

# This will only work with ubuntu or kali. Wazuh does not support Debian 11,12

Here's why:
* Detection rules can be a tricky business and we believe everyone should have access to a strong and growing ruleset.
* Wazuh serves as a great EDR agent, however the default rulesets are rather laxed (in our opinion). We wanted to start building a strong repo of Wazuh rules for the community to implement themselves and expand upon as new threats arise.
* Cybersecurity is hard enough, let's work together :smile:

# Ansible Role: Wazuh SIEM Deployment

An Ansible role that runs the Wazuh SIEM on a Linux system. By default, the password is auto-generated and printed in the logs. As an option, the role variable `wazuh_admin_password` can be used to set it manually.


## Requirements

None.

## Role Variables

Available variables are listed below, along with default values (see `defaults/main.yml`):

    # Wazuh installation script URL
    wazuh_install_script_url: "https://packages.wazuh.com/4.7/wazuh-install.sh"
    # SOCFORTRESS Wazuh rules script URL
    socfortress_rules_script_url: "https://raw.githubusercontent.com/aaladha/Wazuh-Rules/main/wazuh_socfortress_rules.sh"
    # (Optional) Force admin password
    wazuh_admin_password: Wazuh-123


## Example Playbook

```yaml
- hosts: wazuh-siem
  roles:
    - aleemladha.wazuh_server_install
```

## Example Ludus Range Config

```yaml
ludus:
  - vm_name: "{{ range_id }}-wazuh-siem"
    hostname: "{{ range_id }}-wazuh-siem"
    template: kali-x64-desktop-template
    vlan: 20
    ip_last_octet: 2
    ram_gb: 8
    cpus: 4
    linux: true
    testing:
      snapshot: false
      block_internet: false
    roles:
      - aleemladha.wazuh_server_install
    role_vars:
      wazuh_admin_password: Wazuh-123
```

## Ludus setup

```
# Add the role to your ludus host
ludus ansible roles add aleemladha.wazuh_server_install

# Get your config into a file so you can assign to a VM
ludus range config get > config.yml

# Edit config to add the role to the VMs you wish to make an wazuh siem server
ludus range config set -f config.yml

# Deploy the range and access the wazuh SIEM
ludus range deploy

# By default, unless specified manually, the username and password is generated and secured, you can access can it using

ludus range logs -f

```

The output will be

```
ok: [SCCM-wazuh] => {
    "msg": [
        "Username: admin",
        "Password: 8DWmsgBD9*ICMqv?8xnyInr?IMqerI*7"
    ]
}
```


Once deployed, access the wazuh UI at `https://<IP>:`


## Ludus Game of Active Directory (GOAD) Wazuh setup

```
ludus:
  - vm_name: "{{ range_id }}-GOAD-DC01"
    hostname: "{{ range_id }}-DC01"
    template: win2019-server-x64-template
    vlan: 10
    ip_last_octet: 10
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
  - vm_name: "{{ range_id }}-GOAD-DC02"
    hostname: "{{ range_id }}-DC02"
    template: win2019-server-x64-template
    vlan: 10
    ip_last_octet: 11
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
  - vm_name: "{{ range_id }}-GOAD-DC03"
    hostname: "{{ range_id }}-DC03"
    template: win2016-server-x64-template
    vlan: 10
    ip_last_octet: 12
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
  - vm_name: "{{ range_id }}-GOAD-SRV02"
    hostname: "{{ range_id }}-SRV02"
    template: win2019-server-x64-template
    vlan: 10
    ip_last_octet: 22
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
  - vm_name: "{{ range_id }}-GOAD-SRV03"
    hostname: "{{ range_id }}-SRV03"
    template: win2019-server-x64-template
    vlan: 10
    ip_last_octet: 23
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
  - vm_name: "{{ range_id }}-kali"
    hostname: "{{ range_id }}-kali"
    template: kali-x64-desktop-template
    vlan: 10
    ip_last_octet: 99
    ram_gb: 4
    cpus: 2
    linux: true
    testing:
      snapshot: false
      block_internet: false
    roles:
      - aleemladha.wazuh_server_install
    role_vars:
      wazuh_admin_password: Wazuh-123

```

## License

Apache-2.0

## Author Information

This role was created by [Aleem ladha ](https://github.com/aleemladha)

## Resources/Credits
- https://github.com/socfortress/Wazuh-Rules
- https://documentation.wazuh.com/current/installation-guide/index.html
- https://wazuh.com/
- https://github.com/badsectorlabs/ludus_elastic_container

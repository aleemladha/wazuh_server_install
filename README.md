# Ansible Role to Install wazuh SIEM Unified XDR and SIEM protection

# Ansible Role: Wazuh SIEM Deployment

An Ansible role that runs the Wazuh SIEM on a Linux system


## Requirements

None.

## Role Variables


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

#The username and password is generated and secured, you can access can it using

ludus range logs -f

```

#The output will be

```
ok: [SCCM-wazuh] => {
    "msg": [
        "Username: admin",
        "Password: 8DWmsgBD9*ICMqv?8xnyInr?IMqerI*7"
    ]
}
```


- Once deployed, access the wazuh UI at `https://<IP>:`


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

```

## License

Apache-2.0

## Author Information

This role was created by [Aleem ladha ](https://github.com/aleemladha)

## Resources/Credits

- https://documentation.wazuh.com/current/installation-guide/index.html
- https://wazuh.com/
- https://github.com/badsectorlabs/ludus_elastic_container

# Ansible Role to Install wazuh SIEM Unified XDR and SIEM protection

```
cat playbookwazuh.yml 
- name: Install and configure Wazuh Manager
  hosts: wazuh
  become: yes
  roles:
    - wazuh_server
                                      
```


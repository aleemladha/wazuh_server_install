# Ansible Role to Install wazuh SIEM Unified XDR and SIEM protection

### Create a playbook playbookwazuh.yml 
```

- name: Install and configure Wazuh Manager
  hosts: wazuh
  become: yes
  roles:
    - wazuh_server_install
                                      
```

### Create an inventory file and change the IP address according to your lab (vim inventory) and paste the below content

```
wazuh ansible_host=192.168.56.200 ansible_connection=ssh
```


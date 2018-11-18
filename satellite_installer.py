#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Abnerson Malivert <amaliver@redhat.com>
#
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'status': ['stableinterface'],
                    'supported_by': 'core',
                    'version': '1.0'}

DOCUMENTATION = '''
___
module: satellite_installer
author: "Abnerson Malivert"
version_added: "0.0"
short_description: Install satellite 6 server
requirements: satellite_installer
description:
    - Install satellite 6 server
options:

    scenario:
        required: true
        description:
            - Use installation scenario.

    certs_update_server:
        required: false
        description:
            - This option will enforce an update of the HTTPS certificates (default: false).
   
    certs_update_server_ca:
        required: false
        description:
            - This option will enforce an update of the CA used for HTTPS certificates. (default: false).  

    certs_server_cert: 
        required: false
        description:
            - Path to the ssl certificate for https

    certs_server_cert_req:
        required: false
        description:
            - Path to the ssl certificate request for https

    certs_server_key:
        required: false
        description:
            - Path to the ssl key for https

    certs_server_ca_cert:
        required: false
        description:
            - Path to the CA that issued the ssl certificates for https

    foreman_admin_username:
        required: false
        description:
            - Username for the initial admin user 

    foreman_admin_password:  
        required: false
        description:
            - Password of the initial admin user, default is randomly generated 

    foreman_initial_location:
        required: false
        description:
            - Name of an initial location 

    foreman_initial_organization:
        required: false
        description:
            - Name of an initial organization 
    
    foreman_proxy_dhcp:
        required: false
        description:
            - Enable DHCP feature 
    
    foreman_proxy_dhcp_interface:
        required: false
        description:
            - DHCP listen interface   

    foreman_proxy_dhcp_gateway:
        required: false
        description:
            - DHCP pool gateway 

    foreman_proxy_dhcp_range:
        required: false
        description:       
            - Space_separated DHCP pool range 

    foreman_proxy_dhcp_nameservers:
        required: false
        description:       
            - DHCP nameservers, comma_separated 
   
    foreman_proxy_tftp:
        required: false
        description:       
            - Enable TFTP feature 

    foreman_proxy_tftp_servername:
        required: false
        description:
            - Defines the TFTP Servername to use, overrides the name in the subnet declaration 

    foreman_proxy_dns:
        required: false
        description:
            -  Enable DNS feature 

    foreman_proxy_dns_interface:
        required: false
         description:
            - DNS interface 

    foreman_proxy_dns_zone:
        required: false
         description:
            - DNS zone name 

    foreman_proxy_dns_forwarders:
        required: false
         description:
            - DNS forwarders 

    foreman_proxy_dns_reverse:
        required: false
         description:
            - DNS reverse zone name 

    foreman_proxy_content_parent_fqdn:
        required: false
         description:
            - FQDN of the parent node. 

    foreman_proxy_register_in_foreman:
        required: false
         description:
            - Register proxy back in Foreman

    foreman_proxy_foreman_base_url:
        required: false
         description:
            - Base Foreman URL used for REST interaction

    foreman_proxy_trusted_hosts:
        required: false
         description:
            - Only hosts listed will be permitted, empty array to disable authorization 

    foreman_proxy_oauth_consumer_key:
        required: false
         description:
            - OAuth key to be used for REST interaction

    foreman_proxy_oauth_consumer_secret:
        required: false
         description:
            - OAuth secret to be used for REST interaction
'''

EXAMPLES = '''
# Run Satellite 6.3 initial installation with the following configuration
- satellite_installer:
    scenario: satellite
    foreman_admin_username: "admin"
    foreman_admin_password: "password"
    foreman_initial_organization: "RedHat"
    foreman_initial_location: "Tysons"

# Run Satellite 6.3 initial installation with DNS,DHCP and TFTP enabled
- satellite_installer:
    scenario: satellite
    foreman_admin_username: "admin"
    foreman_admin_password: "password"
    foreman_initial_organization: "RedHat"
    foreman_initial_location: "Tysons"
    foreman_proxy_dns: True
    foreman_proxy_dns_interface: "eth0"
    foreman_proxy_dns_zone: "example.com"
    foreman_proxy_dns_forwarders: "172.17.13.1 172.17.13.2"
    foreman_proxy_dns_reverse: "13.17.172.in_addr.arpa"
    foreman_proxy_dhcp: True
    foreman_proxy_dhcp_interface: "eth0"
    foreman_proxy_dhcp_range: "172.17.13.100 172.17.13.150"
    foreman_proxy_dhcp_gateway: "172.17.13.1"
    foreman_proxy_dhcp_nameservers: "172.17.13.2"
    foreman_proxy_tftp: true
    foreman_proxy_tftp_servername: "{{ ansible_fqdn }}"

# Update Satellite 6.3 self_signed certificate with an external CA signed certificate
 - satellite_installer:
    scenario: satellite
    certs_server_cert: "/root/sat_cert/satellite-cert.pem"
    certs_server_cert_req: "/root/sat_cert/satellite-cert-csr.pem"
    certs_server_key:" /root/sat_cert/satellite-cert-key.pem"
    certs_server_ca_cert: "/root/sat_cert/ca-cert-bundle.pem"
    certs_update_server: True 
    certs_update_server_ca: True  
'''
import os
import platform
import socket
import time
from ansible.module_utils._text import to_native

class SatelliteInstaller(object):

    platform = 'Generic'
    distribution = None
    DATE_FORMAT = '%Y_%m_%d'

    def __new__(cls, *args, **kwargs):
        return load_platform_subclass(SatelliteInstaller, args, kwargs)

    def __init__(self, module):
        self.module                            = module
        self.scenario                          = module.params['scenario']
        self.name                              = module.params['name']
        self.certs_update_server               = module.params['certs_update_server']
        self.certs_update_server_ca            = module.params['certs_update_server_ca']
        self.certs_server_cert                 = module.params['certs_server_cert']
        self.certs_server_cert_req             = module.params['certs_server_cert_req']
        self.certs_server_key                  = module.params['certs_server_key']
        self.certs_server_ca_cert              = module.params['certs_server_ca_cert']
        self.foreman_admin_username            = module.params['foreman_admin_username']
        self.foreman_admin_password            = module.params['foreman_admin_password']
        self.foreman_initial_location          = module.params['foreman_initial_location']
        self.foreman_initial_organization      = module.params['foreman_initial_organization']
        self.foreman_proxy_dhcp                = module.params['foreman_proxy_dhcp']
        self.foreman_proxy_dhcp_interface      = module.params['foreman_proxy_dhcp_interface']
        self.foreman_proxy_dhcp_gateway        = module.params['foreman_proxy_dhcp_gateway']
        self.foreman_proxy_dhcp_range          = module.params['foreman_proxy_dhcp_range']
        self.foreman_proxy_dhcp_nameservers    = module.params['foreman_proxy_dhcp_nameservers']
        self.foreman_proxy_dns                 = module.params['foreman_proxy_dns']
        self.foreman_proxy_dns_interface       = module.params['foreman_proxy_dns_interface']
        self.foreman_proxy_dns_zone            = module.params['foreman_proxy_dns_zone']
        self.foreman_proxy_dns_forwarders      = module.params['foreman_proxy_dns_forwarders']
        self.foreman_proxy_dns_reverse         = module.params['foreman_proxy_dns_reverse']
        self.foreman_proxy_tftp                = module.params['foreman_proxy_tftp']
        self.foreman_proxy_tftp_servername     = module.params['foreman_proxy_tftp_servername']
        #self.foreman_proxy_content_parent_fqdn = module.params['foreman_proxy_content_parent_fqdn']
        #self.foreman_proxy_foreman_base_url    = module.params['foreman_proxy_foreman_base_url']
        #self.foreman_proxy_register_in_foreman = module.params['foreman_proxy_register_in_foreman']
        #self.foreman_proxy_trusted_hosts       = module.params['foreman_proxy_trusted_hosts']
        #foreman_proxy_oauth_consumer_secret    = module.params['foreman_proxy_oauth_consumer_secret']
        #foreman_proxy_oauth_consumer_key       = module.params['foreman_proxy_oauth_consumer_key']

        if module.params['foreman_proxy_dhcp_range'] is not None:
            self.foreman_proxy_dhcp_range = ','.join(module.params['foreman_proxy_dhcp_range'])

        if module.params['foreman_proxy_dns_forwarders'] is not None:
            self.foreman_proxy_dns_forwarders = ','.join(module.params['foreman_proxy_dns_forwarders'])
        
        if module.params['foreman_proxy_dhcp_nameservers'] is not None:
            self.foreman_proxy_dhcp_nameservers = ','.join(module.params['foreman_proxy_dhcp_nameservers'])

        if module.params['scenario'] is None:
            raise TypeError

        if (module.params['certs_server_cert'] is not None and module.params['certs_server_key'] is None and 
            module.params['certs_server_cert_req'] is None and 
            module.params['certs_server_ca_cert'] is None):
            raise TypeError

        if (module.params['certs_server_key'] is not None and module.params['certs_server_cert'] is None and
            module.params['certs_server_cert_req'] is None and 
            module.params['certs_server_ca_cert'] is None):
            raise TypeError

        if (module.params['certs_server_cert_req'] is not None and module.params['certs_server_cert'] is None and 
            module.params['certs_server_key'] is None and module.params['certs_server_ca_cert'] is None):
            raise TypeError

        if (module.params['certs_server_ca_cert'] is not None and module.params['certs_server_cert'] is None and 
            module.params['certs_server_key'] is None and 
            module.params['certs_server_ca_cert'] is None):
            raise TypeError

    def execute_command(self, cmd, use_unsafe_shell=False, data=None, obey_checkmode=True):
        if self.module.check_mode and obey_checkmode:
            self.module.debug('In check mode, would have run: "%s"' % cmd)
            return (0, '','')
        else:
            # cast all args to strings ansible_modules_core/issues/4397
            cmd = [str(x) for x in cmd]
            return self.module.run_command(cmd, use_unsafe_shell=use_unsafe_shell, data=data)

    def run_installer(self, command_name='satellite-installer'):
        cmd = [self.module.get_bin_path(command_name, True)]

        if self.scenario is not None:
            cmd.append('--scenario')
            cmd.append(self.scenario)

        if self.foreman_admin_username is not None:
            cmd.append('--foreman-admin-username')
            cmd.append(self.foreman_admin_username )

        if self.foreman_admin_password is not None:
            cmd.append('--foreman-admin-password')
            cmd.append(self.foreman_admin_password)
        
        if self.foreman_initial_organization is not None:
            cmd.append('--foreman-initial-organization')
            cmd.append(self.foreman_initial_organization)

        if self.foreman_initial_location is not None:
            cmd.append('--foreman-initial-location')
            cmd.append(self.foreman_initial_location)

        if self.certs_server_cert is not None:
            cmd.append('--certs-server-cert')
            cmd.append(self.certs_server_cert)

        if self.certs_server_key is not None:
            cmd.append('--certs-server-key')
            cmd.append(self.certs_server_key)

        if self.certs_server_cert_req is not None:
            cmd.append('--certs-server-cert-req')
            cmd.append(self.certs_server_cert_req)

        if self.certs_server_ca_cert is not None:
            cmd.append('--certs-server-ca-cert')
            cmd.append(self.certs_server_ca_cert)

        if self.certs_update_server:
            cmd.append('--certs-update-server')
            cmd.append('true')

        if self.certs_update_server_ca:
            cmd.append('--certs-update-server-ca')
            cmd.append('true')

        if self.foreman_proxy_dhcp:
            cmd.append('--foreman-proxy-dhcp')
            cmd.append('true')

        if self.foreman_proxy_dhcp_interface is not None:
            cmd.append('--foreman-proxy-dhcp-interface')
            cmd.append(self.foreman_proxy_dhcp_interface) 

        if self.foreman_proxy_dhcp_gateway is not None:
            cmd.append('--foreman-proxy-dhcp-gateway')
            cmd.append(self.foreman_proxy_dhcp_gateway) 

        if self.foreman_proxy_dhcp_range is not None:
            cmd.append('--foreman-proxy-dhcp-range')
            cmd.append(self.foreman_proxy_dhcp_range)         

        if self.foreman_proxy_dhcp_nameservers is not None:
            cmd.append('--foreman-proxy-dhcp-nameservers')
            cmd.append(self.foreman_proxy_dhcp_nameservers)

        if self.foreman_proxy_dns:
            cmd.append('--foreman-proxy-dns')
            cmd.append('true') 

        if self.foreman_proxy_dns_interface is not None:
            cmd.append('--foreman-proxy-dns-interface')
            cmd.append(self.foreman_proxy_dns_interface) 

        if self.foreman_proxy_dns_zone is not None:
            cmd.append('--foreman-proxy-dns-zone')
            cmd.append(self.foreman_proxy_dns_zone)

        if self.foreman_proxy_dns_forwarders is not None:
            cmd.append('--foreman-proxy-dns-forwarders')
            cmd.append(self.foreman_proxy_dns_forwarders)

        if self.foreman_proxy_dns_reverse is not None:
            cmd.append('--foreman-proxy-dns-reverse')
            cmd.append(self.foreman_proxy_dns_reverse) 

        if self.foreman_proxy_tftp:
            cmd.append('--foreman-proxy-tftp')
            cmd.append('true')

        if self.foreman_proxy_tftp_servername is not None:
            cmd.append('--foreman-proxy-tftp-servername')
            cmd.append(self.foreman_proxy_tftp_servername) 

        return self.execute_command(cmd)

    
# ===========================================

def main():
    ssh_defaults = {
            'bits': 0,
            'type': 'rsa',
            'passphrase': None,
            'comment': 'ansible_generated on %s' % socket.gethostname()
    }
    module = AnsibleModule(
        argument_spec = dict(
            name=dict(default='satellite-installer', type='str'),
            scenario=dict(required=True, choices=['satellite', 'capsule'], type='str'),
            foreman_admin_username=dict(type='str'),
            foreman_admin_password=dict(type='str', no_log=True),
            foreman_initial_organization=dict(type='str'),
            foreman_initial_location=dict(type='str'),
            certs_server_cert=dict(type='str'),
            certs_server_key=dict(type='str'),
            certs_server_cert_req=dict(type='str'),
            certs_server_ca_cert=dict(type='str'),
            certs_update_server=dict(default='no', type='bool'),
            certs_update_server_ca=dict(default='no', type='bool'),
            foreman_proxy_dhcp=dict(default='no', type='bool'),
            foreman_proxy_dhcp_interface=dict(type='str'),
            foreman_proxy_dhcp_gateway=dict(type='str'),
            foreman_proxy_dhcp_range=dict(type='list'),
            foreman_proxy_dhcp_nameservers=dict(type='list'),
            foreman_proxy_dns=dict(type='bool'),
            foreman_proxy_dns_interface=dict(type='str'),
            foreman_proxy_dns_zone=dict(type='str'),
            foreman_proxy_dns_forwarders=dict(type='list'),
            foreman_proxy_dns_reverse=dict(type='str'),
            foreman_proxy_tftp=dict(type='bool'),
            foreman_proxy_tftp_servername=dict(type='str'),
        ),
    )
    satellite_installer = SatelliteInstaller(module)
    rc = None
    out = ''
    err = ''
    result = {}
    (rc, out, err) = satellite_installer.run_installer()

    if rc is not None and rc != 0:
        module.fail_json(name=satellite_installer.name, msg=err, rc=rc)
    if rc == 0:
        result['changed'] = True
    if rc == 0:
        result = satellite_installer.run_installer()
    else:
        result['satellite-installer'] = err.strip()
    (rc, out, err) = satellite_installer.run_installer()
    

    module.exit_json(name=satellite_installer.name,
                      rc=rc, msg=out.strip())

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()

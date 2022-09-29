import requests
from requests.auth import HTTPBasicAuth
from module.common.logging import get_logger


log = get_logger()
api_url = "/api/"

class SophosUTMClient():

    host_fqdn: None
    port: 443
    username: None
    password: None
    validate_tls_certs: False
    proxy_host: None
    proxy_port: None

    settings = {
        "enabled": True,
        "host_fqdn": None,
        "port": 443,
        "username": None,
        "password": None,
        "validate_tls_certs": False,
        "proxy_host": None,
        "proxy_port": None,
    }


    def __init__(self, settings=None):
        self.parse_config_settings(settings)
        version_info = self.get_version()
        log.info ('sophos version: {0}/{1}'.format( version_info['utm'], version_info['restd']) )

    def get(self, uri, query=None ):
        api_url =   'https://{0}:{1}/api/{2}'.format(  self.host_fqdn, self.port, uri)
        headers = [{'user-agent', 'netbox-sync/1.0', 'content-Type'} ,{'application/json', 'accept' ,'application/json' }]

        response = requests.get(api_url, params=query, verify=self.validate_tls_certs,  auth=HTTPBasicAuth(self.username, self.password))
        return response.json()

# REF_DefaultInternalNetwork
    def get_version(self):
        return self.get('status/version')

    def get_nodes(self):
        return self.get('nodes')

    def get_network_interfaces(self):
        return self.get('objects/network/interface_network')

    def get_itfhw_lag(self):
        return self.get('objects/itfhw/lag')
    
    def get_itfparams_link_aggregation_group(self):
        return self.get('objects/itfparams/link_aggregation_group')


    def get_itfhw_ethernet(self):
        return self.get('objects/itfhw/ethernet')
        
    def get_itfhw_ethernet_used_by(self, ref):
        return self.get('objects/itfhw/ethernet/{}/usedby'.format(ref))

    def get_ethernet_interface(self, ref):
        return self.get('objects/interface/ethernet/{}'.format(ref))
    
    def get_primary_interface(self, primary_interface):
        return self.get('objects/itfparams/primary/{}'.format(primary_interface))

    def get_primary_address(self):
        json =  self.get('objects/itfparams/primary/{}'.format('REF_ItfParamsDefaultInternal'))
        return '{}/{}'.format(json["address"],json["netmask"])

    def parse_config_settings(self, config_settings):
        """
        Validate parsed settings from config file

        Parameters
        ----------
        config_settings: dict
            dict of config settings

        """

        validation_failed = False

        for setting in ["host_fqdn", "port", "username", "password"]:
            if config_settings.get(setting) is None:
                log.error(f"Config option '{setting}' in 'source/{self.name}' can't be empty/undefined")
                validation_failed = True
        
        if validation_failed is True:
            log.error("Config validation failed. Exit!")
            exit(1)
        
        for setting in self.settings.keys():
            setattr(self, setting, config_settings.get(setting))



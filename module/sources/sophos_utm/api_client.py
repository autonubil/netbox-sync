import requests
import re
from requests.auth import HTTPBasicAuth
from module.common.logging import get_logger
import urllib3

log = get_logger()
api_url = "/api/"

re_lag_id = re.compile('^REF_ItfLagLag(\d+)$', re.MULTILINE)
lag_translation= {
    "0": "REF_LagOne",
    "1": "REF_LagTwo",
    "2": "REF_LagThree",
    "3": "REF_LagFour",
    "4": "REF_LagFive",
    "6": "REF_LagSix",
}

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

    lags= None
    all_interfaces= None
    itfparams_secondary= None
    itfparams_secondary_ref= None
    itfparams_primary= None
    itfparams_primary_ref= None

    def __init__(self, settings=None):
        self.parse_config_settings(settings)
        if not self.validate_tls_certs:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    def get_itfhw_lag(self, ref=None):
        if ref:
            return self.get('objects/itfhw/lag/{}'.format(ref))
        else:
            return self.get('objects/itfhw/lag')
    
    def get_itfparams_link_aggregation_group(self, refid=None):
        if refid:
            return self.get('objects/itfparams/link_aggregation_group/{}'.format(refid))
        else:
            return self.get('objects/itfparams/link_aggregation_group')

    def get_lags(self):
        if self.lags:
            return self.lags
        lag_ifs = self.get_itfhw_lag()
        result = {}
        for lag_if in lag_ifs:
            m = re_lag_id.match(lag_if["_ref"])
            if m:
                ifparam_ref = m.group(1)
                lag_name = lag_translation[ifparam_ref]
                params = self.get_itfparams_link_aggregation_group(lag_name)
                params["hardware"] = lag_if["hardware"]
                params["lag_description"] = lag_if["description"]
                params["lag_name"] = lag_if["name"]
                params["itfhw_details"] = {}
                for if_ref in params["itfhw"]:
                    lag_member = self.get_itfhw_ethernet(if_ref)
                    params["itfhw_details"][if_ref] = lag_member
                    if lag_member["name"] == params["name"]:
                        params["itfhw_active"] = lag_member
                        params["speed"] = lag_member["speed"]
                        params["duplex"] = lag_member["duplex"]
                        params["supported_link_modes"] = lag_member["supported_link_modes"]
                result[params["hardware"]] = params
        self.lags = result
        return result
    
    

    def get_itfparams_primary(self, ref =None):
        if not self.itfparams_primary:
                self.itfparams_primary = self.get('objects/itfparams/primary')
                self.itfparams_primary_ref = {}
                for primary in self.itfparams_primary:
                    self.itfparams_primary_ref[primary["_ref"]] = primary
        if ref:
            return self.itfparams_primary_ref[ref]
        else:
            return self.itfparams_primary

#        if ref:
#            return self.get('objects/itfparams/primary/{}'.format(ref))
#        else:
#            return self.get('objects/itfparams/primary')
    

    def get_itfparams_secondary(self, ref =None):
        if not self.itfparams_secondary:
                self.itfparams_secondary = self.get('objects/itfparams/secondary')
                self.itfparams_secondary_ref = {}
                for secondary in self.itfparams_secondary:
                    self.itfparams_secondary_ref[secondary["_ref"]] = secondary
        if ref:
            return self.itfparams_secondary_ref[ref]
        else:
            return self.itfparams_secondary

#    def get_itfparams_secondary(self, ref =None):
#        if ref:
#            return self.get('objects/itfparams/secondary/{}'.format(ref))
#        else:
#            return self.get('objects/itfparams/secondary')


    # def get_network_interface_address(self, ref =None):
    #     if ref:
    #         return self.get('objects/network/interface_address/{}'.format(ref))
    #     else:
    #         return self.get('objects/network/interface_address')

    def get_network_interface_network(self, ref =None):
        if ref:
            return self.get('objects/network/interface_network/{}'.format(ref))
        else:
            return self.get('objects/network/interface_network')


    def expand_itfparams_primary(self, primary):
        primary["interface_address_object"] = self.get_network_interface_address(primary["interface_address"])
        primary["interface_network_object"] = self.get_network_interface_network(primary["interface_network"])
        return primary

    def get_itfparams_primary_ex(self, ref =None):
        if ref:
            primary = self.get_itfparams_primary(ref)
            return self.expand_itfparams_primary(primary)
        else:
            primaries = self.get_itfparams_primary()
            result = []
            for primary in primaries:
                result.append(self.expand_itfparams_primary(primary))
            return result


    def get_itfhw_ethernet(self, ref=None):
        if ref:
            return self.get('objects/itfhw/ethernet/{}'.format(ref))
        else:
            return self.get('objects/itfhw/ethernet')
 
    def get_itfhw_awe_network(self, ref=None):
        if ref:
            return self.get('objects/itfhw/awe_network/{}'.format(ref))
        else:
            return self.get('objects/itfhw/awe_network')

    def get_itfhw_red_server(self, ref=None):
        if ref:
            return self.get('objects/itfhw/red_server/{}'.format(ref))
        else:
            return self.get('objects/itfhw/red_server')
        
    def get_itfhw_ethernet_used_by(self, ref):
        return self.get('objects/itfhw/ethernet/{}/usedby'.format(ref))

    def get_interface_ethernet(self, ref=None):
        if ref:
            return self.get('objects/interface/ethernet/{}'.format(ref))
        else:
            return self.get('objects/interface/ethernet')
    
    def get_interface_vlan(self, ref=None):
        if ref:
            return self.get('objects/interface/vlan/{}'.format(ref))
        else:
            return self.get('objects/interface/vlan')


    def enrich_interface(self,interface):
        hw = interface["itfhw"]
        if hw.startswith("REF_ItfLag"):
            interface["itfhw_object"] = self.get_itfhw_lag(hw)
            lags = self.get_lags()
            interface["itfhw_object"]["hardware_object"] = lags[interface["itfhw_object"]["hardware"]]
        elif hw.startswith("REF_ItfAwe"):
            interface["itfhw_object"] = self.get_itfhw_awe_network(hw)
        elif hw.startswith("REF_ItfRedReds"):
            interface["itfhw_object"] = self.get_itfhw_red_server(hw)
        else:
            interface["itfhw_object"] = self.get_itfhw_ethernet(hw)
        primary_address_ref = interface["primary_address"] 
        if primary_address_ref != "":
            interface["primary_address_object"] = self.get_itfparams_primary(primary_address_ref) #ex?

        interface["additional_address_objects"] = []
        for additonal_address in interface["additional_addresses"]:
            interface["additional_address_objects"].append(self.get_itfparams_secondary(additonal_address))
        return interface

    def get_interfaces(self):
        if not self.all_interfaces:
            self.all_interfaces = []
            used_hardware = {}
            # physical
            for interface in self.get_interface_ethernet():
                interface = self.enrich_interface(interface)
                self.all_interfaces.append(interface)
                ifhw = interface["itfhw_object"]
                if "hardware_object" in ifhw:
                    ifhw = ifhw["hardware_object"]
                used_hardware[ifhw["_ref"]] = True
            
            # configured physical
            for interface in self.get_itfhw_ethernet():
                if not interface["_ref"] in used_hardware:
                    self.all_interfaces.append(interface) 

            # virtual
            for interface in self.get_interface_vlan():
                self.all_interfaces.append(self.enrich_interface(interface))

        return self.all_interfaces

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



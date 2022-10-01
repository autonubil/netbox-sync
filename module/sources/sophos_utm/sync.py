#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
import re

#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
import re

from ipaddress import ip_address, ip_network, ip_interface,IPv4Network
from urllib.parse import unquote

# noinspection PyUnresolvedReferences
from packaging import version
from pytablewriter import IpAddress

from .api_client import SophosUTMClient

from module.sources.common.source_base import SourceBase
from module.common.logging import get_logger, DEBUG3
from module.common.misc import grab, dump, get_string_or_none, plural, quoted_split
from module.common.support import normalize_mac_address, ip_valid_to_add_to_netbox
from module.netbox.object_classes import (
    NetBoxInterfaceType,
    NBTag,
    NBManufacturer,
    NBDeviceType,
    NBPlatform,
    NBClusterType,
    NBClusterGroup,
    NBDeviceRole,
    NBSite,
    NBCluster,
    NBDevice,
    NBVM,
    NBVMInterface,
    NBInterface,
    NBIPAddress,
    NBPrefix,
    NBTenant,
    NBVRF,
    NBVLAN,
    NBCustomField
)

log = get_logger()

re_type_from_license = re.compile('^Type\s=\s(.+?)$', re.MULTILINE)
re_cluster_nodes_from_license = re.compile(
    '^ClusterNodes\s=\s(\d+)$', re.MULTILINE)

# noinspection PyTypeChecker


class SophosUTMHandler(SourceBase):
    """
    Source class to import data from a Sophos UTM instance and add/update NetBox objects based on gathered information
    """

    dependent_netbox_objects = [
        NBTag,
        NBManufacturer,
        NBDeviceType,
        NBPlatform,
        NBClusterType,
        NBClusterGroup,
        NBDeviceRole,
        NBSite,
        NBCluster,
        NBDevice,
        NBVM,
        NBVMInterface,
        NBInterface,
        NBIPAddress,
        NBPrefix,
        NBTenant,
        NBVRF,
        NBVLAN,
        NBCustomField
    ]

    settings = {
        "enabled": True,
        "host_fqdn": None,
        "port": 443,
        "username": None,
        "password": None,
        "validate_tls_certs": False,
        "proxy_host": None,
        "proxy_port": None,
        "vrf": None,
    }

    deprecated_settings = {}

    removed_settings = {}

    init_successful = False
    inventory = None
    name = None
    source_tag = None
    source_type = "sophos_utm"
    enabled = False
    client = SophosUTMClient
    vrf = None
    vrf_object = None
    device_object = None
    raw_interfaces = {}
    interfaces = {}
    interfaces_names = {}

    def __init__(self, name=None, settings=None, inventory=None):

        if name is None:
            raise ValueError(f"Invalid value for attribute 'name': '{name}'.")

        self.inventory = inventory
        self.name = name

        self.parse_config_settings(settings)

        self.source_tag = f"Source: {name}"
        self.site_name = f"sophos: {name}"

        if self.enabled is False:
            log.info(f"Source '{name}' is currently disabled. Skipping")
            return

        self.client = SophosUTMClient(settings)
        self.init_successful = True

    def apply(self):
        """
        Main source handler method. This method is called for each source from "main" program
        to retrieve data from it source and apply it to the NetBox inventory.

        Every update of new/existing objects fot this source has to happen here.

        First try to find and iterate over each inventory file.
        Then parse the system data first and then all components.
        """

        self.get_vrf()
        self.get_device()
        
        self.update_interfaces()

    def get_device(self):
        if isinstance(self.device_object, NBDevice):
            return self.device_object

        nodes = self.client.get_nodes()
        system_id = nodes['settings.system_id']
        device_name = nodes['snmp.device_name']
        internal_device_name = device_name

        model = "SGxxx"
        cluster = False
        cluster_nodes = 1
        cluster_node_id = nodes['ha.node_id']
        cluster_status = nodes['ha.status']
        cluster_mode = nodes['ha.mode']
        license = nodes['licensing.license']
        site_name = nodes['snmp.device_location']

        site_object = None
       

        if license:
            m = re_type_from_license.search(license)
            if m:
                model = m.group(1)
            m = re_cluster_nodes_from_license.search(license)
            if m:
                cluster_nodes = int(m.group(1))
                if cluster_status == 'cluster' and  cluster_nodes > 1:
                    cluster = True
                    device_name = '{}({}/{})'.format(device_name,
                                                     cluster_node_id, cluster_nodes)

        if system_id is None:
            log.warn("Device has no System ID")
            return None

        self.device_object = self.inventory.get_by_data(
            NBDevice, data={"asset_tag": system_id})
        if self.device_object is None:
            self.device_object = self.inventory.get_by_data(
                NBDevice, data={"name": device_name, "site": site_object})
        if self.device_object is None:
            self.device_object = self.inventory.get_by_data(
                NBDevice, data={"name": internal_device_name, "site": site_object})
        if self.device_object is None:
            self.device_object = self.inventory.get_by_data(
                NBDevice, data={"display": device_name})
        if self.device_object is None:
            self.device_object = self.inventory.get_by_data(
                NBDevice, data={"display": internal_device_name})

        if self.device_object:
            device_name = grab(self.device_object, "data.name")

        manufacturer_object = self.inventory.add_update_object(
            NBManufacturer, data={"name": "Sophos"},  source=self)
        role_object = self.inventory.add_update_object(
            NBDeviceRole, data={"name": "Firewall"},  source=self)
        device_type_object = self.inventory.add_update_object(
            NBDeviceType, data={"model": model, "manufacturer": manufacturer_object,},  source=self)
    
        if device_type_object:
            site_name = grab(self.device_object, "data.site.data.name", fallback=site_name)

        if site_name:
            site_object = self.inventory.get_by_data(
                NBSite, data={"name": site_name})
            if site_object is None and site_name and site_name != "":
                site_object = self.inventory.add_update_object(
                    NBSite, data={"name": site_name}, source=self)

        device_data = {
            "name": device_name,
            "asset_tag": system_id,
        }
        if cluster:
            if cluster_mode == "master":
                device_data["status"] = "active"
            else:
                device_data["status"] = "offline"
        else:
            device_data["status"] = "active"


        if site_object:
            device_data["site"] = site_object
        if role_object:
            device_data["device_role"] = role_object
        if device_type_object:
            device_data["device_type"] = device_type_object

        self.device_object = self.inventory.add_update_object(
            NBDevice, data=device_data, read_from_netbox=False, source=self)

        # device_data["primary_ip4"] =  self.inventory.add_update_object(NBIPAddress, data={"address": self.client.get_primary_address(), "vrf": self.vrf_object })
        #self.device_object = self.inventory.add_update_object(
        #    NBDevice, data=device_data, read_from_netbox=False, source=self)

        return self.device_object

    def update_hw_interfaces(self, all_interfaces):
        for interface in all_interfaces:
            if interface["_type"] == 'itfhw/ethernet':
                name = interface["name"]
                hw =interface["hardware"]
                nic_type = NetBoxInterfaceType('other')
                types = interface["supported_link_modes"].split(',')
                for test_type in types:
                    if test_type.startswith(interface["speed"]):
                        nic_type = NetBoxInterfaceType(test_type.split("/")[0])
                        if nic_type.get_common_type() == "other":
                            nic_type = NetBoxInterfaceType(int(interface["speed"]))
                        break

                interface_data = {
                    "name":name,
                    "device": self.device_object,
                    "label":hw,
                    "description": interface["description"],
                    "mac_address": interface["mac"].upper(),
                    "duplex": interface["duplex"].lower(),
                    "speed": int(interface["speed"])*1000,
                    "type": nic_type.get_common_type(),
                }
                 
                self.inventory.add_update_object(NBInterface, data=interface_data)

    def add_addresse(self,nbinterface, address):
        ip4 = "{}/{}".format(address["address"],address["netmask"])
        ip4net = IPv4Network(ip4, strict = False)
        prefix_data = {
            "prefix": ip4net,
            "site": grab(self.device_object, "data.site"),
            "description": grab(nbinterface,"data.name"),
            "vrf": self.vrf_object,
        }
        self.inventory.add_update_object(NBPrefix, data=prefix_data, source=self)

        address_data = {
            "address": ip4,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": nbinterface,
            "description":  address["name"]
        }
        if "hostname" in address and address["hostname"] != "":
            address_data["dns_name"] = address["hostname"]
        return self.inventory.add_update_object(NBIPAddress, data=address_data, source=self)
        

    def add_addresses(self,nbinterface, interface):
        if "primary_address_object" in interface:
            primary_address_object = interface["primary_address_object"]
            nbpimary_address = self.add_addresse(nbinterface, primary_address_object)
            # nbinterface.primary_ip4 = nbpimary_address

        if "additional_address_objects" in interface:
            additional_address_objects = interface["additional_address_objects"]
            for additional_address_object in additional_address_objects:
                self.add_addresse(nbinterface, additional_address_object)


    def update_ethernet_interfaces(self, all_interfaces):
        for interface in all_interfaces:
            ifhw = None
            if "itfhw_object" in interface:
                ifhw = interface["itfhw_object"]
                # dig into active lag W`HW`
                if "hardware_object" in ifhw:
                    ifhw = ifhw["hardware_object"]
                hw =ifhw["hardware"]
            if ifhw and ifhw["_type"] == 'itfhw/awe_network':
                interface_data = {
                    "name":interface_data["name"],
                    "enabled": interface["status"],
                    "device": self.device_object,
                    "label":hw,
                    "description": interface["comment"],
                    "mac_address": ifhw["mac"].upper(),
                    "mtu": interface["mtu"],
                    "type": "other-wireless",
                }
                if ifhw["vlantag"] != "":
                    interface_data["mode"] = "access"
                    interface_data["untagged_vlan"] = self.inventory.add_update_object(NBVLAN, data={"vid": int(ifhw["vlantag"]), "name": ifhw["ssid"], "site": grab(self.device_object ,"data.site")  }, source=self)
                    
                nbinterface = self.inventory.add_update_object(NBInterface, data=interface_data, source=self)
                self.add_addresses(nbinterface, interface)
                continue
            if interface["_type"] == 'interface/ethernet':
                name = interface["name"]
                if  "supported_link_modes" in ifhw:
                    types = ifhw["supported_link_modes"].split(',')
                    for test_type in types:
                        if test_type.startswith(ifhw["speed"]):
                            nic_type = NetBoxInterfaceType(test_type.split("/")[0])
                            if nic_type.get_common_type() == "other":
                                nic_type = NetBoxInterfaceType(int(ifhw["speed"]))
                            break
                else:
                    nic_type = NetBoxInterfaceType('other')

                interface_data = {
                    "name":name,
                    "device": self.device_object,
                    "label":hw,
                    "description": interface["comment"],
                    "mac_address": ifhw["mac"].upper(),
                    "type": nic_type.get_common_type(),
                    "enabled": interface["status"],
                    "connection_status": interface["link"],
                    "mtu": interface["mtu"],
                }

                if interface["link"]:
                    interface_data["mark_connected"] = True
                    
                if interface["_ref"] == "REF_IntEthManagement":
                    interface_data["mgmt_only"] = True
                nbinterface = self.inventory.add_update_object(NBInterface, data=interface_data, source=self)
                self.add_addresses(nbinterface, interface)

    def update_interfaces(self):
        # ensure interfaces
        all_interfaces = self.client.get_interfaces()
        self.update_hw_interfaces(all_interfaces)
        self.update_ethernet_interfaces(all_interfaces)
        return

            # 'interface/ethernet'

        # first ensure LAGs
        lag_hw = {}
        lag_ifs = {}
        for interface in self.client.get_lags():
            interface_data = {
                "name":interface["lag_name"],
                "device": self.device_object,   
                "label":interface["hardware"],
                "description": interface["lag_description"],
                "mac_address": interface["virtual_mac"].upper(),
                "duplex": interface["duplex"].lower(),
                "speed": int(interface["speed"])*1000,
                "type": 'lag',
                "connection_status": interface["status"]
            }
            lag_hw[interface["_ref"]] =interface["itfhw"]
            lag_ifs[interface["_ref"]] = self.inventory.add_update_object(NBInterface, data=interface_data)
            self.interfaces[interface["_ref"]] = lag_ifs[interface["_ref"]]
            self.raw_interfaces[interface["_ref"]] = interface
            self.interfaces_names[interface["_ref"]] = interface["name"]

        # hardware
        for interface in self.client.get_itfhw_ethernet():
            name = interface["name"]
            hw =interface["hardware"]
            id = None
            for existing_interface in existing_interfaces:
                test_name = grab(existing_interface, "data.name")
                pat = '\\b{}\\b'.format(hw)
                if re.match(pat, test_name):
                    id = existing_interface.nb_id

            nic_type = NetBoxInterfaceType('other')
            types = interface["supported_link_modes"].split(',')
            for test_type in types:
                if test_type.startswith(interface["speed"]):
                    nic_type = NetBoxInterfaceType(test_type.split("/")[0])
                    if nic_type.get_common_type() == "other":
                        nic_type = NetBoxInterfaceType(int(interface["speed"]))
                    break

            interface_data = {
                "name":name,
                "device": self.device_object,
                "label":hw,
                "description": interface["description"],
                "mac_address": interface["mac"].upper(),
                "duplex": interface["duplex"].lower(),
                "speed": int(interface["speed"])*1000,
                "type": nic_type.get_common_type(),
            }
            
            if id:
                interface_data["id"] = id

            # lag?
            for ifid, hwlist in lag_hw.items():
                for hw in hwlist:
                    if hw == interface["_ref"]:
                        if lag_ifs[ifid].nb_id  > 0:
                            interface_data["lag"] = lag_ifs[ifid]
                        break

            nbinterface = self.inventory.add_update_object(NBInterface, data=interface_data),
            self.interfaces[interface["_ref"]] = nbinterface
            self.raw_interfaces[interface["_ref"]] = interface
            self.interfaces_names[interface["_ref"]] = interface["name"]

 

    def get_vrf(self):
        if isinstance(self.vrf_object, NBVRF):
            return self.vrf_object

        if self.vrf is None:
            return None
        for vrf in self.inventory.get_all_items(NBVRF):
            if grab(vrf, "data.name") == self.vrf:
                log.debug(f"vrf '{self.vrf}' was resolved")
                self.vrf_object = vrf
                return self.vrf_object

        vrf_data = {
            "name": self.vrf
        }
        self.vrf_object = self.inventory.add_object(
            NBVRF, data=vrf_data, read_from_netbox=False, source=self)
        return self.vrf_object

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
                log.error(
                    f"Config option '{setting}' in 'source/{self.name}' can't be empty/undefined")
                validation_failed = True

        if validation_failed is True:
            log.error("Config validation failed. Exit!")
            exit(1)

        for setting in self.settings.keys():
            setattr(self, setting, config_settings.get(setting))

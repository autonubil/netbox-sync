#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
from pydoc import resolve
import re

#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
import re

from ipaddress import ip_address, ip_network, ip_interface, IPv4Network
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
    NBObjectList,
    NBTag,
    NBManufacturer,
    NBDeviceType,
    NBPlatform,
    NBClusterType,
    NBClusterGroup,
    NBDeviceRole,
    NBSiteGroup,
    NBSite,
    NBSiteGroup,
    NBCluster,
    NBDevice,
    NBVM,
    NBVMInterface,
    NBInterface,
    NBIPAddress,
    NBPrefix,
    NBTenant,
    NBTenantGroup,
    NBVRF,
    NBVLAN,
    NBCustomField
)

log = get_logger()

re_type_from_license = re.compile('^Type\s=\s(.+?)$', re.MULTILINE)
re_cluster_nodes_from_license = re.compile(
    '^ClusterNodes\s=\s(\d+)$', re.MULTILINE)

re_address_name_group = re.compile('^([a-z]{2,}\-[a-z]{2,}\-[a-z]{2,})\-([a-z]+)$')
re_address_name_zone = re.compile('^([a-z]{2,}\-[a-z]{2,}\-[a-z]{2,})\-([a-z]+)(\d)(\-[a-z]+)?$')
re_tenant = re.compile('^([a-z]{2,})\-([a-z]{2,})\-([a-z]{2,})$')


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
        NBSiteGroup,
        NBCluster,
        NBDevice,
        NBVM,
        NBVMInterface,
        NBInterface,
        NBIPAddress,
        NBPrefix,
        NBTenant,
        NBTenantGroup,
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
        "site_group": None,
        "site_a": None,
        "site_b": None,
        "site_floating": None,
        "site_spare": None,
        "tenant_group": None,
        "create_company_tenant_group": False,
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

    site_group= None
    site_a=None
    site_b=None
    site_floating=None
    site_spare=None
    tenant_group=None
    create_company_tenant_group=False

    site_group_object= None
    site_object= None
    site_a_object=None
    site_b_object=None
    site_floating_object=None
    site_spare_object=None
    tenant_group_object=None


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

        if not self.enabled: 
            return

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

        # if site_name == "" and 
        if self.site_a != "" and self.site_b != "":
            site_name =  [self.site_a, self.site_b ][((cluster_node_id-1) % 2)]

        self.site_object = None

        site_data={
        }

        if self.tenant_group:
            self.tenant_group_object = self.inventory.get_by_data(
                NBTenantGroup, data={"name": self.tenant_group})
            if self.tenant_group_object is None and self.tenant_group and self.tenant_group != "":
                self.tenant_group_object = self.inventory.add_update_object(
                    NBTenantGroup, data={"name": self.tenant_group}, source=self)
            if self.tenant_group_object:
                site_data["tenant_group"] = self.tenant_group_object

        if self.site_group:
            self.site_group_object = self.inventory.get_by_data(
                NBSiteGroup, data={"name": self.site_group})
            if self.site_group_object is None and self.site_group and self.site_group != "":
                self.site_group_object = self.inventory.add_update_object(
                    NBSiteGroup, data={"name": self.site_group}, source=self)
            if self.site_group_object:
                site_data["group"] = self.site_group_object

        if site_name:
            site_data["name"] = site_name
            self.site_object = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.site_object is None and site_name and site_name != "":
                self.site_object = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_a:
            site_data["name"] = self.site_a
            self.site_a_object = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.site_a_object is None:
                self.site_a_object = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_b:
            site_data["name"] = self.site_b
            self.site_b_object = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.site_b_object is None:
                self.site_b_object = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_floating:
            site_data["name"] = self.site_floating
            self.site_floating_object = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.site_floating_object is None:
                self.site_floating_object = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_spare:
            site_data["name"] = self.site_spare
            self.site_spare_object = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.site_spare_object is None:
                self.site_spare_object = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if system_id is None:
            log.warn("Device has no System ID")
            return None

        self.device_object = self.inventory.get_by_data(
            NBDevice, data={"asset_tag": system_id})
        if self.device_object is None:
            self.device_object = self.inventory.get_by_data(
                NBDevice, data={"name": device_name, "site": self.site_object})
        if self.device_object is None:
            self.device_object = self.inventory.get_by_data(
                NBDevice, data={"name": internal_device_name, "site": self.site_object})
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


        if self.site_object:
            device_data["site"] = self.site_object
        if role_object:
            device_data["device_role"] = role_object
        if device_type_object:
            device_data["device_type"] = device_type_object

        device_data["primary_ip4"] =  self.inventory.add_update_object(NBIPAddress, data={"address": self.client.get_primary_address(), "vrf": self.vrf_object }, source=self)

        self.device_object = self.inventory.add_update_object(
            NBDevice, data=device_data, read_from_netbox=False, source=self)

        
        return self.device_object

    def resolve_tenant(self,candidate):
        """
        Try to find the best matching existing tenant. 
        If non is found crate it. A company tenant group can optionally be created.
        """
        m = re_tenant.match(candidate)
        if m:
            tenant_data = {"slug": candidate }
            if self.tenant_group_object:
                tenant_group = self.tenant_group_object
                if self.create_company_tenant_group:
                    if m.group(1) == grab(self.tenant_group_object, "data.slug"):
                        tenant_group =    self.tenant_group_object
                    else:
                        tenant_group = self.inventory.add_update_object(NBTenantGroup, data={"name": m.group(1), "parent":self.tenant_group_object}, source=self)
            tenant_object = self.inventory.get_by_data(NBTenantGroup, data={"slug": candidate})
            if not tenant_object:
                tenant_data["name"] = candidate

            if tenant_group:
                tenant_data["group"] = tenant_group

            return self.inventory.add_update_object(NBTenant, data=tenant_data, source=self)

        m = re_address_name_zone.match(candidate)         
        if m:
            return self.resolve_tenant(m.group(1))
        m = re_address_name_group.match(candidate)         
        if m:
            return self.resolve_tenant(m.group(1))

        for tenant in self.inventory.get_all_items(NBTenant):
            tenant_name = grab(tenant,"data.slug")
            m = re_tenant.match(tenant_name)
            if m:
                company = m.group(1)
                if candidate.startswith("{}-".format(company)) or "-{}-".format(company) in candidate:
                    self.resolve_tenant(tenant_name)

        return None

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
                 
                self.inventory.add_update_object(NBInterface, data=interface_data, source=self)
    def add_addresse(self,nbinterface, address, nbvlan = None):
        ip4 = "{}/{}".format(address["address"],address["netmask"])
        self.add_prefix(nbinterface,  address["name"], ip4,nbvlan)

        address_data = {
            "address": ip4,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": nbinterface,
            "description":  "gateway for {}".format(address["name"])
        }
        if "hostname" in address and address["hostname"] != "":
            address_data["dns_name"] = address["hostname"]
        return self.inventory.add_update_object(NBIPAddress, data=address_data, source=self)

    def add_prefix(self,nbinterface,name, ip4, nbvlan = None):
        # exanio specific 
        if ip4.endswith("/22") and name.endswith("-transfer"):
            parent_name = name[0:-9]
            parent_ip4 = ip4[0:-1]+"0"
            self.add_prefix(nbinterface,parent_name, parent_ip4, None)

        ip4net = IPv4Network(ip4, strict = False)
        prefix_data = {
            "prefix": ip4net,
            "site": None,
            "description": name,
            "vrf": self.vrf_object,
        }
        tenant = grab(nbinterface, "data.tenant")
        if not tenant:
            tenant = self.resolve_tenant(name)
        if tenant:
            prefix_data["tenant"] = tenant
        else:
            prefix_data["tenantgroup"] = self.tenant_group_object

        if (nbvlan):
            prefix_data["vlan"] = nbvlan
        if self.site_group_object:
            prefix_data["sitegroup"] = self.site_group_object
        if self.site_floating_object:
            
            m = re_address_name_zone.match(name)
            if m:
                zone = m.group(3)
                if zone == "1" and self.site_floating_object:
                    prefix_data["site"] = self.site_floating_object
                if zone == "2" and self.site_a_object:
                    prefix_data["site"] = self.site_a_object
                if zone == "3" and self.site_b_object:
                    prefix_data["site"] = self.site_b_object
                if zone == "4" and self.site_spare_object:
                    prefix_data["site"] = self.site_spare_object
        else:
            prefix_data["site"] = self.site_object
        
        self.inventory.add_update_object(NBPrefix, data=prefix_data, source=self)

        

    def add_addresses(self,nbinterface, interface, nbvlan = None):
        if "primary_address_object" in interface:
            primary_address_object = interface["primary_address_object"]
            self.add_addresse(nbinterface, primary_address_object, nbvlan)
            # nbinterface.primary_ip4 = nbpimary_address

        if "additional_address_objects" in interface:
            additional_address_objects = interface["additional_address_objects"]
            for additional_address_object in additional_address_objects:
                self.add_addresse(nbinterface, additional_address_object, nbvlan)


    def update_ethernet_interfaces(self, all_interfaces):
        for interface in all_interfaces:
            ifhw = None
            name = interface["name"]
            tenant_object = self.resolve_tenant(name)
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
                self.raw_interfaces[hw] = nbinterface
                continue
            if interface["_type"] == 'interface/ethernet':
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
                if tenant_object:
                   interface["tenant"]: tenant_object

                if interface["link"]:
                    interface_data["mark_connected"] = True
                    
                if interface["_ref"] == "REF_IntEthManagement":
                    interface_data["mgmt_only"] = True
                nbinterface = self.inventory.add_update_object(NBInterface, data=interface_data, source=self)
                self.add_addresses(nbinterface, interface)
                self.raw_interfaces[hw] = nbinterface
                continue
            if interface["_type"] == 'interface/vlan':
                interface_data = {
                    "name":name,
                    "label":hw,
                    "device": self.device_object,
                    "description": interface["comment"],
                    "mac_address": ifhw["mac"].upper(),
                    "type": nic_type.get_common_type(),
                    "enabled": interface["status"],
                    "connection_status": interface["link"],
                    "mtu": interface["mtu"],
                }
                if tenant_object:
                    interface["tenant"]: tenant_object
                else:
                    interface["tenantgrop"]: self.tenant_group_object

                if interface["vlantag"] != "":
                    vlan_data = {"vid": int(interface["vlantag"]), "name": interface["name"] }

                    nbvlanlist = NBObjectList()
                    if self.site_floating_object and self.site_group_object:
                        vlan_data["sitegroup"]=self.site_group_object
                    else:
                        vlan_data["site"]=grab(self.device_object ,"data.site")

                    if tenant_object:
                        vlan_data["tenant"]: tenant_object
                    else:
                        vlan_data["tenantgrop"]: self.tenant_group_object

                    nbvlan = self.inventory.add_update_object(NBVLAN, data = vlan_data, source=self)
                    nbvlanlist.append(nbvlan)

                    interface_data["label"]= "VLAN {} on {}".format(interface["vlantag"],  hw)
                    interface_data["mode"]="tagged"
                    interface_data["tagged_vlans"]= nbvlanlist

                if interface["link"]:
                    interface_data["mark_connected"] = True
                    
                if interface["_ref"] == "REF_IntEthManagement":
                    interface_data["mgmt_only"] = True

#                if hw in self.raw_interfaces:
#                    parentid = self.raw_interfaces[hw].nb_id
#                    if parentid > 0:
#                        interface_data["parent"] = parentid

                nbinterface = self.inventory.add_update_object(NBInterface, data=interface_data, source=self)
                self.add_addresses(nbinterface, interface, nbvlan)


    def update_interfaces(self):
        # ensure interfaces
        all_interfaces = self.client.get_interfaces()
        self.update_hw_interfaces(all_interfaces)
        self.update_ethernet_interfaces(all_interfaces)
 

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

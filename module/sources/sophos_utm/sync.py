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
from .config import CheckSophosConfig

from module.sources.common.source_base import SourceBase
from module.common.logging import get_logger, DEBUG3
from module.common.misc import grab, dump, get_string_or_none, plural, quoted_split
from module.common.support import normalize_mac_address
from module.netbox.inventory import NetBoxInventory
from module.netbox.object_classes import (
    NBFHRPGroupItem,
    NBFHRPGroupAssignment,
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
    NBInterface,
    NBIPAddress,
    NBPrefix,
    NBTenant,
    NBTenantGroup,
    NBVRF,
    NBVLANGroup,
    NBVLAN,
    NBCustomField
)

log = get_logger()

re_type_from_license = re.compile('^Type\s=\s(.+?)$', re.MULTILINE)
re_cluster_nodes_from_license = re.compile(
    '^ClusterNodes\s=\s(\d+)$', re.MULTILINE)

re_address_name_group = re.compile('^([a-z]{2,}\-[a-z]{2,}\-[a-z]{2,})\-([a-z]+)$')
re_address_name_zone = re.compile('^([a-z]{2,}\-[a-z]{2,}\-[a-z]{2,})\-([a-z0-9]+)(\d)(\-[a-z0-9]+)?$')
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
        NBInterface,
        NBIPAddress,
        NBPrefix,
        NBTenant,
        NBFHRPGroupItem,
        NBFHRPGroupAssignment,
        NBTenantGroup,
        NBVRF,
        NBVLANGroup,
        NBVLAN,
        NBCustomField
    ]

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
    raw_interfaces = {}

    site_group= None
    group_vlans = None
    site_a=None
    site_b=None
    site_floating=None
    site_spare=None
    tenant_group=None
    create_company_tenant_group=False
    cluster_sync=False
    fhrp_id = 1

    nb_vrf = None
    nb_device = None
    nb_site_group= None
    nb_site= None
    nb_site_a=None
    nb_site_b=None
    nb_site_floating=None
    nb_site_spare=None
    nb_tenant_group=None
    is_cluster = False
    is_active_active = False
    internal_device_name = "Sophos"

    def __init__(self, name=None):

        if name is None:
            raise ValueError(f"Invalid value for attribute 'name': '{name}'.")

        self.inventory = NetBoxInventory()
        self.name = name

        settings_handler = CheckSophosConfig()
        settings_handler.source_name = self.name
        self.settings = settings_handler.parse()

        self.parse_config_settings(self.settings)

        self.source_tag = f"Source: {name}"
        self.site_name = f"sophos: {name}"

        if self.enabled is False:
            log.info(f"Source '{name}' is currently disabled. Skipping")
            return

        self.client = SophosUTMClient(self.settings)
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

        if self.nb_device:    
            self.update_interfaces()
            if self.is_cluster and self.cluster_sync:
                self.nb_device = None
                self.get_device(True)
                if self.nb_device:
                    self.update_interfaces()

    def ensure_nb_objects(self, site_name):
        
        site_data={
        }

        if self.tenant_group and not self.nb_tenant_group:
            self.nb_tenant_group = self.inventory.get_by_data(
                NBTenantGroup, data={"name": self.tenant_group})
            if self.nb_tenant_group is None and self.tenant_group and self.tenant_group != "":
                self.nb_tenant_group = self.inventory.add_update_object(
                    NBTenantGroup, data={"name": self.tenant_group}, source=self)
            if self.nb_tenant_group:
                site_data["tenant_group"] = self.nb_tenant_group

        if self.site_group and not self.nb_site_group:
            self.nb_site_group = self.inventory.get_by_data(
                NBSiteGroup, data={"name": self.site_group})
            if self.nb_site_group is None and self.site_group and self.site_group != "":
                self.nb_site_group = self.inventory.add_update_object(
                    NBSiteGroup, data={"name": self.site_group}, source=self)
            if self.nb_site_group:
                site_data["group"] = self.nb_site_group

        if site_name and not self.nb_site:
            site_data["name"] = site_name
            self.nb_site = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.nb_site is None and site_name and site_name != "":
                self.nb_site = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_a and not self.nb_site_a:
            site_data["name"] = self.site_a
            self.nb_site_a = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.nb_site_a is None:
                self.nb_site_a = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_b and not self.nb_site_b:
            site_data["name"] = self.site_b
            self.nb_site_b = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.nb_site_b is None:
                self.nb_site_b = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_floating and not self.nb_site_floating:
            site_data["name"] = self.site_floating
            self.nb_site_floating = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.nb_site_floating is None:
                self.nb_site_floating = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

        if self.site_spare and not self.nb_site_spare:
            site_data["name"] = self.site_spare
            self.nb_site_spare = self.inventory.get_by_data(
                NBSite, data=site_data)
            if self.nb_site_spare is None:
                self.nb_site_spare = self.inventory.add_update_object(
                    NBSite, data=site_data, source=self)

    def get_device(self, invert_cluster=False):
        if isinstance(self.nb_device, NBDevice):
            return self.nb_device

        nodes = self.client.get_nodes()
        
        device_name = nodes['snmp.device_name']
        self.internal_device_name = device_name

        model = "SGxxx"

        cluster_nodes = 1
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
                if (cluster_status == 'cluster' or cluster_status == 'hot_standby') and  cluster_nodes > 1:
                    self.is_cluster = True
                    cluster_node_id = nodes['ha.node_id']
                    if invert_cluster:
                        if cluster_node_id == 1:
                            cluster_node_id = 2
                        else:
                            cluster_node_id = 1
                    device_name = '{}({}/{})'.format(device_name,
                                                     cluster_node_id, cluster_nodes)

                    # if site_name == "" and 
                    if self.site_a != "" and self.site_b != "":
                        site_name =  [self.site_a, self.site_b ][((cluster_node_id-1) % 2)]

        self.nb_site = None
        self.ensure_nb_objects(site_name)

        nb_device = None
        if nb_device is None:
            nb_device = self.inventory.get_by_data(
                NBDevice, data={"name": device_name, "site": self.nb_site})
        if nb_device is None:
            nb_device = self.inventory.get_by_data(
                NBDevice, data={"display": device_name})
        if nb_device is None:
            nb_device = self.inventory.get_by_data(
                NBDevice, data={"name": self.internal_device_name, "site": self.nb_site})
        if nb_device is None:
            nb_device = self.inventory.get_by_data(
                NBDevice, data={"display": self.internal_device_name})

        if nb_device:
            device_name = grab(nb_device, "data.name")

        manufacturer_object = self.inventory.add_update_object(
            NBManufacturer, data={"name": "Sophos"},  source=self)
        role_object = self.inventory.add_update_object(
            NBDeviceRole, data={"name": "Firewall"},  source=self)
        device_type_object = self.inventory.add_update_object(
            NBDeviceType, data={"model": model, "manufacturer": manufacturer_object,},  source=self)
    
        if device_type_object:
            site_name = grab(nb_device, "data.site.data.name", fallback=site_name)
        device_data = {
            "name": device_name,
        }
        self.is_active_active = False
        if self.is_cluster:
            if cluster_mode == "master" and not cluster_status == 'hot_standby':
                self.is_active_active = True
                device_data["status"] = "active"
            else:
                if cluster_status == 'cluster':
                    device_data["status"] = "active"
                if cluster_status == 'hot_standby' and invert_cluster:
                    device_data["status"] = "offline"
                
        else:
            device_data["status"] = "active"


        if self.nb_site:   
            device_data["site"] = self.nb_site
        if role_object:
            device_data["device_role"] = role_object
        if device_type_object:
            device_data["device_type"] = device_type_object

        if not invert_cluster:
            if not self.is_active_active:
                device_data["primary_ip4"] =  self.inventory.add_update_object(NBIPAddress, data={"address": self.client.get_primary_address(), "vrf": self.nb_vrf }, source=self)

        self.nb_device = self.inventory.add_update_object(
            NBDevice, data=device_data,  source=self)
        

    def resolve_tenant(self,candidate):
        """
        Try to find the best matching existing tenant. 
        If non is found crate it. A company tenant group can optionally be created.
        """
        m = re_tenant.match(candidate)
        tenant_group=None
        if m:
            tenant_data = {"slug": candidate }
            if self.nb_tenant_group:
                tenant_group = self.nb_tenant_group
                if self.create_company_tenant_group:
                    if m.group(1) == grab(self.nb_tenant_group, "data.slug"):
                        tenant_group =    self.nb_tenant_group
                    else:
                        tenant_group = self.inventory.add_update_object(NBTenantGroup, data={"name": m.group(1), "parent":self.nb_tenant_group}, source=self)
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
                hw =interface["hardware"]
                name = "{}@{}".format(hw, grab(self.nb_device, "data.name"))
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
                    "device": self.nb_device,
                    "label":hw,
                    "description": interface["description"],
                    "mac_address": interface["mac"].upper(),
                    "duplex": interface["duplex"].lower(),
                    "speed": int(interface["speed"])*1000,
                    "type": nic_type.get_common_type(),
                }
                self.inventory.add_update_object(NBInterface, data=interface_data, source=self)

    def add_interface_address(self,nbinterface, address, nbvlan = None):
        
        ip4 = "{}/{}".format(address["address"],address["netmask"])
        self.add_prefix(nbinterface,  address["name"], ip4,nbvlan)

        address_data = {
            "address": ip4,
            "description":  "gateway for {}".format(address["name"])
        }

        if self.is_active_active:
            address_data["assigned_object_type"]= "ipam.fhrpgroup"
            address_data["assigned_object_id"]= self.get_fhrp(nbinterface)
        else:
            address_data["assigned_object_type"]= "dcim.interface"
            address_data["assigned_object_id"]= nbinterface

        if "hostname" in address and address["hostname"] != "":
            address_data["dns_name"] = address["hostname"]

        return self.inventory.add_update_object(NBIPAddress, data=address_data, source=self)

    def add_prefix(self,nbinterface,name, ip4, nbvlan = None):
        # exanio specific 
        parent = None
        if ip4.endswith("/22"):
            parts = name.split("-")
            if len(parts) > 3:
                if name.endswith("-transfer"):
                    parent_name = name[0:-9]
                    parent_ip4 = ip4[0:-1]+"0"
                    self.add_prefix(nbinterface, parent_name, parent_ip4, None)

                parts = name.split("-")
                new_name = "-".join(parts[0:3])+"-"+parts[3][0]+"0"
                parent_ip4 = ip4[0:-1]+"3"
                self.add_prefix(nbinterface,new_name, parent_ip4, nbvlan)

        ip4net = IPv4Network(ip4, strict = False)
        prefix_data = {
            "prefix": ip4net,
            "site": None,
            "description": name,
            "vrf": self.nb_vrf,
        }

        tenant = grab(nbinterface, "data.tenant")
        if not tenant:
            tenant = self.resolve_tenant(name)
        if tenant:
            prefix_data["tenant"] = tenant
        else:
            prefix_data["tenantgroup"] = self.nb_tenant_group

        if (nbvlan):
            prefix_data["vlan"] = nbvlan
        #if self.nb_site_group:
        #    prefix_data["sitegroup"] = self.nb_site_group
        if self.nb_site_floating:
            m = re_address_name_zone.match(name)
            if m:
                zone = m.group(3)
                if zone == "0" and self.nb_site_floating:
                    prefix_data["site"] = self.nb_site_floating
                elif zone == "1" and self.nb_site_a:
                    prefix_data["site"] = self.nb_site_a
                elif zone == "2" and self.nb_site_b:
                    prefix_data["site"] = self.nb_site_b
                elif zone == "3" and self.nb_site_spare:
                    prefix_data["site"] = self.nb_site_spare
                elif zone == "4" and self.nb_site_spare:
                    prefix_data["site"] = self.nb_site_spare
                else:
                    print(zone)
        else:
            prefix_data["site"] = self.nb_site
        
        return self.inventory.add_update_object(NBPrefix, data=prefix_data, source=self)

    def get_fhrp(self, nbinterface):
        fhrp_data = {
                "group_id": self.fhrp_id,
                "ip_addresses": [],
                "protocol": "vrrp2",
                "description": "{} cluster addresses for {}".format(self.internal_device_name, grab(nbinterface, "data.label"))
            }
        return self.inventory.add_update_object(
            NBFHRPGroupItem, data=fhrp_data,  source=self)


    def add_addresses(self,nbinterface, interface, nbvlan = None):
        if "primary_address_object" in interface:
            primary_address_object = interface["primary_address_object"]
            ipaddress = self.add_interface_address(nbinterface, primary_address_object, nbvlan)
            if self.is_active_active:
                fhrp = self.get_fhrp(nbinterface)
                grab(fhrp,"data.ip_addresses").append(ipaddress)
                self.inventory.add_update_object(NBFHRPGroupAssignment, data={ "group": fhrp, "interface_id": nbinterface, "priority": 10, "interface_type": "dcim.interface" }, source=self)

            # nbinterface.primary_ip4 = nbpimary_address

        if "additional_address_objects" in interface:
            additional_address_objects = interface["additional_address_objects"]
            for additional_address_object in additional_address_objects:
                ipaddress =  self.add_interface_address(nbinterface, additional_address_object, nbvlan)
                if self.is_active_active:
                    fhrp = self.get_fhrp(nbinterface)
                    grab(fhrp,"data.ip_addresses").append(ipaddress)
                    self.inventory.add_update_object(NBFHRPGroupAssignment, data={ "group": fhrp, "interface_id": nbinterface, "priority": 10, "interface_type": "dcim.interface" }, source=self)


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
                    "device": self.nb_device,
                    "label":hw,
                    "description": interface["comment"],
                    "mac_address": ifhw["mac"].upper(),
                    "mtu": interface["mtu"],
                    "type": "other-wireless",
                }
                if ifhw["vlantag"] != "":
                    interface_data["mode"] = "access"
                    vlan_data = self.associate_vlan({"vid": int(ifhw["vlantag"]), "name": ifhw["ssid"]  },  {"site": grab(self.nb_device ,"data.site")} )
                    interface_data["untagged_vlan"] = self.inventory.add_update_object(NBVLAN, vlan_data, source=self)
                    
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
                    "device": self.nb_device,
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
                    "device": self.nb_device,
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
                    interface["tenantgroup"]: self.nb_tenant_group

                if interface["vlantag"] != "":
                    vlan_data = {"vid": int(interface["vlantag"]), "name": interface["name"] }

                    nbvlanlist = NBObjectList()
                    
                    site_data = {}
                    if self.nb_site_group:
                        site_data["sitegroup"]=self.nb_site_group
                    if not self.nb_site_floating:
                        site_data["site"]=grab(self.nb_device ,"data.site")

                    if tenant_object:
                        vlan_data["tenant"]: tenant_object
                    vlan_data["tenantgroup"]: self.nb_tenant_group

                    vlan_data = self.associate_vlan(vlan_data, site_data)
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
        if isinstance(self.nb_vrf, NBVRF):
            return self.nb_vrf

        if self.vrf is None:
            return None
        for vrf in self.inventory.get_all_items(NBVRF):
            if grab(vrf, "data.name") == self.vrf:
                log.debug(f"vrf '{self.vrf}' was resolved")
                self.nb_vrf = vrf
                return self.nb_vrf

        vrf_data = {
            "name": self.vrf
        }
        self.nb_vrf = self.inventory.add_object(
            NBVRF, data=vrf_data, source=self)
           
        return self.nb_vrf

    def parse_config_settings(self, config_settings):
        """
        Validate parsed settings from config file

        Parameters
        ----------
        config_settings: dict
            dict of config settings

        """

        for setting in [
            "vrf",
            "site_group",
            "group_vlans",
            "site_a",
            "site_b",
            "site_floating",
            "site_spare",
            "tenant_group",
            "create_company_tenant_group",
            "cluster_sync",
            "fhrp_id"]:
                if hasattr(self.settings, setting):
                    setattr(self, setting, getattr(self.settings, setting))
        


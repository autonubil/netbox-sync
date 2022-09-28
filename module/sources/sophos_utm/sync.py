#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
import re

#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
import re

from ipaddress import ip_address, ip_network, ip_interface
from urllib.parse import unquote

# noinspection PyUnresolvedReferences
from packaging import version

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

        self.import_prefixes()

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
            "status": "active",
            "primary_ip4": self.inventory.add_update_object(NBIPAddress, data={"address": self.client.get_primary_address(), "vrf": self.vrf_object, }),
        }
        if site_object:
            device_data["site"] = site_object
        if role_object:
            device_data["device_role"] = role_object
        if device_type_object:
            device_data["device_type"] = device_type_object

        self.device_object = self.inventory.add_update_object(
            NBDevice, data=device_data, read_from_netbox=False, source=self)

        return self.device_object

    def get_vrf(self):
        if isinstance(self.vrf_object, NBVRF):
            return self.vrf_object

        if self.vrf is None:
            return None

        this_vrf = None

        for vrf in self.inventory.get_all_items(NBVRF):
            if grab(self, "data.name") == self.vrf:
                log.debug(f"vrf '{self.vrf}' was resolved")
                self.vrf_object = vrf
                return self.vrf_object

        vrf_data = {
            "name": self.vrf
        }
        self.vrf_object = self.inventory.add_object(
            NBVRF, data=vrf_data, read_from_netbox=False, source=self)
        return self.vrf_object

    def import_prefixes(self):
        interfaces = self.client.get_network_interfaces()
        vrf = self.get_vrf()
        device = self.get_device()

        log.info('if: {}'.format(interfaces))

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

# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2023 Ricardo Bartels. All rights reserved.
#
#  netbox-sync.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import os

from module.config import source_config_section_name
from module.config.base import ConfigBase
from module.config.option import ConfigOption
from module.sources.common.conifg import *
from module.common.logging import get_logger
from module.common.misc import quoted_split
from module.sources.common.permitted_subnets import PermittedSubnets

log = get_logger()


class CheckSophosConfig(ConfigBase):

    section_name = source_config_section_name
    source_name = None
    source_name_example = "my-sophos-example"

    def __init__(self):
        self.options = [
            ConfigOption(**config_option_enabled_definition),

            ConfigOption(**{**config_option_type_definition, "config_example": "sophos_utm"}),

            ConfigOption("host_fqdn",
                         str,
                         description="sophos host name",
                         config_example="fw.initech.com",
                         mandatory=True),

            ConfigOption("port",
                         int,
                         description="sophos api port",
                         config_example=4444,
                         mandatory=True),
            ConfigOption("username",
                         str,
                         description="sophos api username",
                         config_example="admin",
                         mandatory=True),
            ConfigOption("password",
                         str,
                         description="sophos api password",
                         config_example="secret",
                         mandatory=True),


            ConfigOption("vrf",
                         str,
                         description="vrf to use for IP-Prefixes",
                         config_example="internal",
                         mandatory=True),

            ConfigOption("cluster_sync",
                         bool,
                         description="Sync cluster partner",
                         default_value=False),

            ConfigOption("group_vlans",
                         bool,
                         description="Group VLANS (dcim.sitegroup or dcim.site)",
                         mandatory=False),
                         

            ConfigOption("site_a",
                         str,
                         description="Zone site a",
                         mandatory=False),                         
            ConfigOption("site_b",
                         str,
                         description="Zone site b",
                         mandatory=False),                         
            ConfigOption("site_floating",
                         str,
                         description="Zone site floating",
                         mandatory=False),                         
            ConfigOption("site_spare",
                         str,
                         description="Zone site spare"),                         
            ConfigOption("tenant_group",
                         str,
                         description="Tenant group for new tenants",
                         default_value="autonubil",
                         mandatory=False),                         
            
            ConfigOption("fhrp_id",
                         int,
                         description="virtual ip froup id",
                         config_example=1,
                         mandatory=False),

             ConfigOption("create_company_tenant_group",
                         bool,
                         description="Auto create group for company tenants",
                         default_value=True),

        ]

        super().__init__()

    def validate_options(self):
        return



    # settings = {
    #     "enabled": True,
    #     "host_fqdn": None,
    #     "port": 443,
    #     "username": None,
    #     "password": None,
    #     "validate_tls_certs": False,
    #     "proxy_host": None,
    #     "proxy_port": None,
    #     "vrf": None,
    #     "site_group": None,
    #     "group_vlans": None,
    #     "site_a": None,
    #     "site_b": None,
    #     "site_floating": None,
    #     "site_spare": None,
    #     "tenant_group": None,
    #     "create_company_tenant_group": False,
    #     "cluster_sync": False,
    #     "fhrp_id": 1,
    # }

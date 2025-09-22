# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141392");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-08-23 16:34:16 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron AirMedia Presentation Gateway Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Crestron AirMedia Presentation Gateway
  devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

if ("Crestron Electronics AM-" >!< sysdesc)
  exit(0);

version = "unknown";
model = "unknown";

# Crestron Electronics AM-100 (Version 1.1.0.14)
# Crestron Electronics AM-100 (Version 1.4.0.13)
# nb: The following is a AM-101 device (see consolidation for special handling)
# Crestron Electronics AM-100 (Version 2.8.0.32)
mod = eregmatch(pattern: "Crestron Electronics (AM\-[0-9]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

vers = eregmatch(pattern: "Version ([0-9.]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "crestron_airmedia/detected", value: TRUE);
set_kb_item(name: "crestron_airmedia/snmp/detected", value: TRUE);
set_kb_item(name: "crestron_airmedia/snmp/port", value: port);
set_kb_item(name: "crestron_airmedia/snmp/" + port + "/model", value: model);
set_kb_item(name: "crestron_airmedia/snmp/" + port + "/fw_version", value: version);
set_kb_item(name: "crestron_airmedia/snmp/" + port + "/concluded", value: sysdesc);

exit(0);

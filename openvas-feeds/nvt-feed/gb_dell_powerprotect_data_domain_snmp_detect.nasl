# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140142");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell PowerProtect Data Domain Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Dell PowerProtect Data Domain.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

if ("Data Domain OS" >!< sysdesc)
  exit(0);

version = "unknown";
model = "unknown";

set_kb_item(name: "dell/powerprotect/data_domain/detected", value: TRUE);
set_kb_item(name: "dell/powerprotect/data_domain/snmp/detected", value: TRUE);
set_kb_item(name: "dell/powerprotect/data_domain/snmp/port", value: port);
set_kb_item(name: "dell/powerprotect/data_domain/snmp/" + port + "/concluded", value: sysdesc);

# Data Domain OS 6.0.0.9-544198
# Data Domain OS 8.6.1.10-1226405
vers = eregmatch(pattern: "Data Domain OS ([0-9.-]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "dell/powerprotect/data_domain/snmp/" + port + "/version", value: version);
set_kb_item(name: "dell/powerprotect/data_domain/snmp/" + port + "/model", value: model);

exit(0);

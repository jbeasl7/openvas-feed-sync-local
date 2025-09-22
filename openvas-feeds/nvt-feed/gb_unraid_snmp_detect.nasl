# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153875");
  script_version("2025-01-29T05:37:24+0000");
  script_tag(name:"last_modification", value:"2025-01-29 05:37:24 +0000 (Wed, 29 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-27 09:02:17 +0000 (Mon, 27 Jan 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Unraid OS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Unraid OS.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Linux Tower 6.6.68-Unraid #1 SMP PREEMPT_DYNAMIC Tue Dec 31 13:42:37 PST 2024 x86_64
if (egrep(pattern: "^Linux [^0-9]*[0-9.]-+Unraid", string: sysdesc, icase: FALSE))
  exit(0);

version = "unknown";

set_kb_item(name: "unraid/detected", value: TRUE);
set_kb_item(name: "unraid/snmp/detected", value: TRUE);
set_kb_item(name: "unraid/snmp/port", value: port);
set_kb_item(name: "unraid/snmp/" + port + "/concluded", value: sysdesc);

vers = eregmatch(pattern: "^Linux [^0-9]*([0-9.]+)\-Unraid", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "unraid/snmp/" + port + "/version", value: version);

exit(0);

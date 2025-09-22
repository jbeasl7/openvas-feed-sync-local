# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.154038");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-19 05:20:20 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik RouterOS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of MikroTik RouterOS.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# RouterOS RB951Ui-2HnD
# RouterOS CHR
if (sysdesc !~ "^RouterOS ")
  exit(0);

version = "unknown";

set_kb_item(name: "mikrotik/routeros/detected", value: TRUE);
set_kb_item(name: "mikrotik/routeros/snmp/detected", value: TRUE);
set_kb_item(name: "mikrotik/routeros/snmp/port", value: port);

concluded = "  SNMP Banner: " + chomp(sysdesc);

sw_oid = "1.3.6.1.4.1.14988.1.1.4.4.0";

sw_vers = snmp_get(port: port, oid: sw_oid);
if (sw_vers =~ "^[0-9]") {
  version = chomp(sw_vers);
  concluded += '\n  Version concluded from: "' + sw_vers + '" via OID: "' + sw_oid;
}

set_kb_item(name: "mikrotik/routeros/snmp/" + port + "/version", value: version);
set_kb_item(name: "mikrotik/routeros/snmp/" + port + "/concluded", value: concluded);

exit(0);

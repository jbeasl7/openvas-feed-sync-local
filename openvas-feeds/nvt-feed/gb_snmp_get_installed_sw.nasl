# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106913");
  script_version("2025-07-10T05:42:18+0000");
  script_tag(name:"last_modification", value:"2025-07-10 05:42:18 +0000 (Thu, 10 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-06-29 15:32:58 +0700 (Thu, 29 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Installed Software Packages Enumeration (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl", "toolcheck.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available", "Tools/Present/libsnmp");

  script_tag(name:"summary", value:"SNMP based enumeration of installed software packages on
  Linux/Unix systems/devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc || ("Linux" >!< sysdesc && sysdesc !~ "(Free|Net|Open)BSD") && sysdesc !~ "^Cisco Identity Services Engine")
  exit(0);

# nb: We limit it to max 800 entries which should be enough for our purpose for now...
for (i = 1; i <= 800; i++) {
  oid = "1.3.6.1.2.1.25.6.3.1.2." + i;

  res = snmp_get(port: port, oid: oid);

  if (!res)
    break;

  sw += oid + "|" + res + "|";
}

if (sw) {
  set_kb_item(name: "SNMP/installed_software/available", value: TRUE);
  set_kb_item(name: "SNMP/" + port + "/installed_software", value: sw);
}

exit(0);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152968");
  script_version("2024-08-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-08-28 05:05:33 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-27 04:10:13 +0000 (Tue, 27 Aug 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology NAS / DiskStation Manager Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_dependencies("gb_snmp_get_installed_sw.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/installed_software/available");

  script_tag(name:"summary", value:"SNMP based detection of Synology NAS / DiskStation Manager
  (DSM).");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdescr = snmp_get_sysdescr(port: port);
if (!sysdescr || sysdescr !~ "^Linux")
  exit(0);

sw_oid = "1.3.6.1.4.1.6574.1.5.3.0";
vers = snmp_get(port: port, oid: sw_oid);
if (!vers || vers !~ "^DSM ")
  exit(0);

version = "unknown";
model = "unknown";

set_kb_item(name: "synology/dsm/detected", value: TRUE);
set_kb_item(name: "synology/dsm/snmp/detected", value: TRUE);
set_kb_item(name: "synology/dsm/snmp/port", value: port);

sw_vers = eregmatch(pattern: "^DSM ([0-9.-]+)", string: vers);
if (!isnull(sw_vers[1])) {
  version = sw_vers[1];
  set_kb_item(name: "synology/dsm/snmp/" + port + "/concludedVers", value: vers);
  set_kb_item(name: "synology/dsm/snmp/" + port + "/concludedVersOID", value: sw_oid);
}

mod_oid = "1.3.6.1.4.1.6574.1.5.1.0";
mod = snmp_get(port: port, oid: mod_oid);
if (mod) {
  model = mod;
  set_kb_item(name: "synology/dsm/snmp/" + port + "/concludedMod", value: mod);
  set_kb_item(name: "synology/dsm/snmp/" + port + "/concludedModOID", value: mod_oid);
}

set_kb_item(name: "synology/dsm/snmp/" + port + "/version", value: version);
set_kb_item(name: "synology/dsm/snmp/" + port + "/model", value: model);

exit(0);

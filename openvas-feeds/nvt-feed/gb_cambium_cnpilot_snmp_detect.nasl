# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140629");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Cambium Networks cnPilot devices.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);

if (!sysdesc || sysdesc !~ "^(Cambium )?cnPilot")
  exit(0);

set_kb_item(name: "cambium/cnpilot/detected", value: TRUE);
set_kb_item(name: "cambium/cnpilot/snmp/detected", value: TRUE);
set_kb_item(name: "cambium/cnpilot/snmp/port", value: port);

model = "unknown";
version = "unknown";

# cnPilot R200P 4.3.1-R1
# Cambium cnPilot E410 Access Point
mod = eregmatch(pattern: "cnPilot ([^ ]+)", string: sysdesc);
if (!isnull(mod[1])) {
  model = mod[1];
  concluded = "    " + sysdesc;
}

vers = eregmatch(pattern: "cnPilot " + model + " ([0-9.]+-R.*)", string: sysdesc);
if (!isnull(vers[1])) {
  version = vers[1];
} else {
  sw_oid = "1.3.6.1.4.1.17713.22.1.1.1.8.0";

  sw_vers = snmp_get(port: port, oid: sw_oid);

  # 4.2.3.1-r9
  if (sw_vers =~ "^([0-9]+\.[0-9]+)") {
    version = toupper(chomp(sw_vers));

    concluded += '\n    Version concluded from: "' + sw_vers + '" via OID: "' + sw_oid;
  }
}

set_kb_item(name: "cambium/cnpilot/snmp/" + port + "/model", value: model);
set_kb_item(name: "cambium/cnpilot/snmp/" + port + "/fw_version", value: version);
if (concluded)
  set_kb_item(name: "cambium/cnpilot/snmp/" + port + "/concluded", value: concluded);

exit(0);

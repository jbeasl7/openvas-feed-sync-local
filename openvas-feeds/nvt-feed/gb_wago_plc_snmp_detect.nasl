# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141767");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-12-07 13:21:00 +0700 (Fri, 07 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of WAGO PLC Controllers.");

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

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# WAGO 750-881 PFC ETHERNET
# WAGO IO-IPC
if (sysdesc =~ "^WAGO ") {

  version = "unknown";

  set_kb_item(name: "wago_plc/detected", value: TRUE);
  set_kb_item(name: "wago_plc/snmp/detected", value: TRUE);
  set_kb_item(name: "wago_plc/snmp/port", value: port);
  set_kb_item(name: "wago_plc/snmp/" + port + "/concluded", value: sysdesc);

  mod = eregmatch(pattern: "WAGO (.+)", string: sysdesc);
  if (!isnull(mod[1]))
    set_kb_item(name: "wago_plc/snmp/" + port + "/model", value: mod[1]);

  # nb: Some systems like e.g. 750-8212 in firmware version 03.06.x using "libwagosnmp" /
  # "WagoLibNetSnmp.lib" seems to not support this OID tree and no alternative has been found so far

  fw_oid = "1.3.6.1.4.1.13576.10.1.10.4.0"; # "Complete firmwarestring"
  fw_res = snmp_get(port: port, oid: fw_oid);
  # 01.06.31
  # 01.05.15
  # 01.08.01
  # 01.04.15
  # 01.02.10
  # 02.01.05
  vers = eregmatch(pattern: "^([0-9.]+)", string: fw_res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "wago_plc/snmp/" + port + "/concludedfw", value: "Firmware from SNMP OID " + fw_oid + ": " + vers[0]);
  }

  set_kb_item(name: "wago_plc/snmp/" + port + "/fw_version", value: version);

  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171560");
  script_version("2025-06-27T05:41:33+0000");
  script_tag(name:"last_modification", value:"2025-06-27 05:41:33 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-25 14:43:58 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link Device Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"SNMP based detection of D-Link devices.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysname_available = get_kb_item("SNMP/sysname/available");
sysloc_available = get_kb_item("SNMP/syslocation/available");

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

if (sysloc_available) {
  info = get_kb_item("SNMP/" + port + "/syslocation");
  model = get_kb_item("SNMP/" + port + "/sysname");
  model_oid = get_kb_item("SNMP/" + port + "/sysname/oid");
} else if (sysname_available) {
  info = get_kb_item("SNMP/" + port + "/sysname");
  model = sysdesc;
}

if (!info || info !~ "D-Link")
  exit(0);
# nb: Will not handle unknown models for now, until properly tested
if (!model)
  exit(0);

version = "unknown";
concluded = model;

if (model =~ "^DIR" || model =~ "^DWR" || model =~ "^DSL"  || model =~ "^DCS" || model =~ "^DSR" ||
    model =~ "^DAP" || model =~ "^DHP") {
  info = eregmatch(pattern: "^([A-Z]+)-([0-9a-zA-Z]+)$", string: model);
  type = info[1];
  detect_type = tolower(type);
  model = info[2];
} else {
  detect_type = "device";
}

if (sysdesc =~ "Software Version") {
  # Software Version RU_1.31
  vers = eregmatch(pattern: "Software Version ([A-Z]+_)?([.0-9]+)", string: sysdesc);
  if (!isnull(vers[2])) {
    version = vers[2];
    fw_concluded = sysdesc;
  }
}

set_kb_item(name: "d-link/" + detect_type + "/snmp/" + port + "/model", value: model);
set_kb_item(name: "d-link/" + detect_type + "/snmp/" + port + "/fw_version", value: version);
set_kb_item(name: "d-link/" + detect_type + "/detected", value: TRUE);
set_kb_item(name: "d-link/" + detect_type + "/snmp/detected", value: TRUE);
set_kb_item(name: "d-link/" + detect_type + "/snmp/port", value: port);
set_kb_item(name: "d-link/" + detect_type + "/snmp/" + port + "/concluded", value: concluded);
if (model_oid)
  set_kb_item(name: "d-link/" + detect_type + "/snmp/" + port + "/concludedOID", value: model_oid);
if (fw_concluded)
  set_kb_item(name: "d-link/" + detect_type + "/snmp/" + port + "/fw_concluded", value: fw_concluded);

exit(0);

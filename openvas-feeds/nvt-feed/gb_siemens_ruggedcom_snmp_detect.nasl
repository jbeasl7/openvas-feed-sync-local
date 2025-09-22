# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140810");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-02-26 13:19:50 +0700 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens RUGGEDCOM Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Siemens RUGGEDCOM devices.");

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

if ("Siemens, SIMATIC NET, RUGGEDCOM" >!< sysdesc && "RuggedCom" >!< sysdesc)
  exit(0);

set_kb_item(name: "siemens_ruggedcom/detected", value: TRUE);
set_kb_item(name: "siemens_ruggedcom/snmp/detected", value: TRUE);
set_kb_item(name: "siemens_ruggedcom/snmp/port", value: port);

# Siemens, SIMATIC NET, RUGGEDCOM RM1224 NAM, 6GK6 108-4AM00-2DA2, HW: Version 1, FW: Version V04.01.02, SVPH8159590
# RuggedCom RX1500 (this RX devices are running ROX)
prod = eregmatch(pattern: 'RUGGEDCOM ([^\r\n,]+)', string: sysdesc, icase: TRUE);
if (!isnull(prod[1]))
  set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/model", value: prod[1]);

vers = eregmatch(pattern: "FW: Version V([0-9.]+)", string: sysdesc);
if (!isnull(vers[1])) {
  set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/version", value: vers[1]);
  set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/concluded", value: vers[0]);
}
else {
  fw_oid = "1.3.6.1.4.1.15004.4.2.3.3.0";
  fw_res = snmp_get(port: port, oid: fw_oid);
  vers = eregmatch(pattern: "ROX ([0-9.]+)", string: fw_res);
  if (!isnull(vers[1])) {
    set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/version", value: vers[1]);
    set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/concludedOID", value: fw_oid);
    set_kb_item(name: "siemens_ruggedcom/isROX", value: TRUE);
  }
}

exit(0);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106097");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-06-15 15:54:49 +0700 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC S7 Device Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Siemens SIMATIC S7 devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

# Siemens, SIMATIC S7, CPU-1200, 6ES7 214-1BE30-0XB0 SZVA2YYY007305  , 1, V.1.0.2, SZVA2YYY007305
# Siemens, SIMATIC S7, CPU315-2 PN/DP, 6ES7 315-2EH14-0AB0 , HW: 7, FW: V3.2.11, S C-H4C233962016
if (egrep(string: sysdesc, pattern: "Siemens, SIMATIC( S7,)|(, S7)")) {
  mo = eregmatch(pattern: "SIMATIC( S7)?, (S7-|CPU-|IM|CPU)([^,]+)", string: sysdesc);
  model = mo[3];

  version = "unknown";
  sp = split(sysdesc, sep: ",", keep: FALSE);
  if (!isnull(sp[5])) {
    ver = eregmatch(pattern: "V(\.)?([0-9.]+)", string: sp[5]);
    if (!isnull(ver[2]))
      version = ver[2];
  }

  modtype = eregmatch(pattern: ", ((CPU-|IM|CPU)[^,]+)", string: sysdesc);
  if (!isnull(modtype[1]))
    set_kb_item(name: "siemens/simatic_s7/snmp/modtype", value: modtype[1]);

  module = eregmatch(pattern: "(6ES7 [^, ]+)", string: sysdesc);
  if (!isnull(module[1]))
    set_kb_item(name: "siemens/simatic_s7/snmp/module", value: module[1]);

  set_kb_item(name: "siemens/simatic_s7/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/snmp/model", value: model);
  if (version != "unknown")
    set_kb_item(name: "siemens/simatic_s7/snmp/" + port + "/version", value: version);
  set_kb_item(name: "siemens/simatic_s7/snmp/port", value: port);
}

exit(0);

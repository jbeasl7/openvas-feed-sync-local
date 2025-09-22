# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140736");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-02-01 15:08:26 +0700 (Thu, 01 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC CP Device Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Siemens SIMATIC CP devices.");

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

# Siemens, SIMATIC NET, CP 343-1 Lean, 6GK7 343-1CX10-0XE0, HW: Version 3, FW: Version V2.2.20, VPA2517023
if (egrep(string: sysdesc, pattern: "Siemens, SIMATIC NET, CP")) {
  set_kb_item(name: 'simatic_cp/detected', value: TRUE);
  set_kb_item(name: "simatic_cp/snmp/detected", value: TRUE);
  set_kb_item(name: 'simatic_cp/snmp/port', value: port);

  sp = split(sysdesc, sep: ",", keep: FALSE);

  # Model
  if (!isnull(sp[2])) {
    model = eregmatch(pattern: '(CP.*)', string: sp[2]);
    if (!isnull(model[1]))
      set_kb_item(name: 'simatic_cp/snmp/' + port + '/model', value: model[1]);
  }

  # Version
  if (!isnull(sp[5])) {
    version = eregmatch(pattern: "V([0-9.]+)", string: sp[5]);
    if (!isnull(version[1]))
      set_kb_item(name: 'simatic_cp/snmp/' + port + '/version', value: version[1]);
  }

  # Module
  if (!isnull(sp[3])) {
    module = eregmatch(pattern: '^ (.*)', string: sp[3]);
    set_kb_item(name: 'simatic_cp/snmp/' + port + '/module', value: module[1]);
  }

  # HW Version
  if (!isnull(sp[4])) {
    hw = eregmatch(pattern: "HW: Version ([0-9]+)", string: sp[4]);
    set_kb_item(name: 'simatic_cp/snmp/' + port + '/hw_version', value: hw[1]);
  }
}

exit(0);

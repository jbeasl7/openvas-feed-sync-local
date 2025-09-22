# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146405");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-07-30 06:59:34 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Epson Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Epson printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
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

# EPSON Built-in Gigabit Ether Print Server
# EPSON Built-in 11b/g/n Print Server
# EPSON Built-in 11b/g & 10/100 Print Server
# EPSON AL-MX200DNF
if (sysdesc =~ "^EPSON ") {
  model = "unknown";
  fw_version = "unknown";
  hw_version = "unknown";

  set_kb_item(name: "epson/printer/detected", value: TRUE);
  set_kb_item(name: "epson/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "epson/printer/snmp/port", value: port);
  set_kb_item(name: "epson/printer/snmp/" + port + "/banner", value: sysdesc);

  # EPSON L6190 Series
  # LU14L6
  # EPSON SC-P20000 Series
  mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
  m = snmp_get(port: port, oid: mod_oid);
  mod = eregmatch(pattern: "^(EPSON )?([^ \r\n]+).*", string: m);
  if (!isnull(mod[2])) {
    model = mod[2];
    set_kb_item(name: "epson/printer/snmp/" + port + "/concludedMod", value: mod[0]);
    set_kb_item(name: "epson/printer/snmp/" + port + "/concludedModOID", value: mod_oid);
  }

  fw_oid = "1.3.6.1.2.1.43.15.1.1.6.1.1";
  vers = snmp_get(port: port, oid: fw_oid);
  if (!isnull(vers) && vers != "") {
    fw_version = vers;
    set_kb_item(name: "epson/printer/snmp/" + port + "/concludedFwOID", value: fw_oid);
  } else {
    fw_oid = "1.3.6.1.2.1.43.5.1.1.17.1";
    vers = snmp_get(port: port, oid: fw_oid);
    if (!isnull(vers) && vers != "") {
      fw_version = vers;
      set_kb_item(name: "epson/printer/snmp/" + port + "/concludedFwOID", value: fw_oid);
    }
  }

  set_kb_item(name: "epson/printer/snmp/" + port + "/model", value: model);
  set_kb_item(name: "epson/printer/snmp/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "epson/printer/snmp/" + port + "/hw_version", value: hw_version);
}

exit(0);

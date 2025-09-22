# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142834");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-09-03 01:48:27 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Lexmark Printer Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Lexmark printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
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

# Lexmark CX510de version NH61.GM.N634 kernel 3.0.0 All-N-1
# Lexmark XM3250 version MXTGM.052.024 kernel 4.11.12-yocto-standard-75677a77e1bb29a486d543e92014998b All-N-1
# Lexmark XC2235 version CXTZJ.052.024 kernel 4.11.12-yocto-standard-7c6e6fab694c88eb205167072e999ab1 All-N-1
# Note: Nxxxx.xxx.xxx is the network version and not the firmware version
if (sysdesc =~ "^Lexmark") {
  set_kb_item(name: 'lexmark_printer/detected', value: TRUE);
  set_kb_item(name: 'lexmark_printer/snmp/detected', value: TRUE);
  set_kb_item(name: 'lexmark_printer/snmp/port', value: port);
  set_kb_item(name: 'lexmark_printer/snmp/' + port + '/concluded', value: sysdesc );

  model = eregmatch(pattern: "Lexmark ([^ ]+)", string: sysdesc);
  if (!isnull(model[1]))
    set_kb_item(name: 'lexmark_printer/snmp/' + port + '/model', value: model[1]);

  version = eregmatch(pattern: "version ([^ ]+)", string: sysdesc);
  if (!isnull(version[1]) && version[1] !~ "^N")
    set_kb_item(name: 'lexmark_printer/snmp/' + port + '/fw_version', value: version[1]);
}

exit(0);

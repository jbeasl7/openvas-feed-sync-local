# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143662");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2020-03-31 08:53:09 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of DrayTek Vigor devices.

  This script performs SNMP based detection of DrayTek Vigor devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
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

# DrayTek Corporation, Router Model: Vigor2960, Version: 1.4.4_Beta/1.4.4, Build Date/Time: 2019-07-07 23:29:57
# DrayTek Corporation, Router Model: Vigor2860 Series, Version: 3.8.9.4_STD, Build Date/Time:Jan 30 2019 15:54:34, CPU Usage: 6%, Memory Usage:86%
# Linux Draytek 2.4.20-br251 #7 Fri Feb 1 16:01:37 CST 2008 POLO
# DrayTek Corporation
if (sysdesc !~ "^DrayTek.+Router Model" && sysdesc !~ "^DrayTek Corporation" && sysdesc !~ "^Linux Draytek ")
  exit(0);

set_kb_item(name: "draytek/vigor/detected", value: TRUE);
set_kb_item(name: "draytek/vigor/snmp/port", value: port);
set_kb_item(name: "draytek/vigor/snmp/" + port + "/concluded", value: sysdesc);

model = "unknown";
version = "unknown";

mod = eregmatch(pattern: "Router Model: Vigor([0-9]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

vers = eregmatch(pattern: "Version: ([^/,]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "draytek/vigor/snmp/" + port + "/model", value: model);
set_kb_item(name: "draytek/vigor/snmp/" + port + "/version", value: version);

exit(0);

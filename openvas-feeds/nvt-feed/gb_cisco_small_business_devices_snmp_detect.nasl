# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105767");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-06-16 09:06:38 +0200 (Thu, 16 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Small Business Device Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Cisco Small Business devices.");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Linux, Cisco Small Business RV130 (RV130), Version 1.0.2.7
# Linux, Cisco Small Business RV325, Version 1.1.1.06 Fri Dec 6 11:10:41 CST 2013
# Linux, Cisco Small Business ISA550(ISA550-K9), Version 1.0.3 Wed May 23 18:50:29 CST 2012
# Linux, Cisco Small Business WAP4410N-A, Version 2.0.6.1
# Linux 2.6.21.5-lvl7-dev, Cisco Small Business WAP121 (WAP121-E-K9), Version 1.0.5.3 Thu Sep 11 03:49:18 EDT 2014
# Linux, Cisco Small Business RV320, Version 1.2.1.14 Thu Aug 13 14:25:16 CST 2015
# Linux, Cisco Small Business RV134W (RV134W-E-K9), version 1.0.1.11 2018-01-05T17:48:42
if (sysdesc !~ "^Linux[^,]*, Cisco Small Business")
  exit(0);

version = "unknown";

set_kb_item(name: "cisco/small_business/detected", value: TRUE);
set_kb_item(name: "cisco/small_business/snmp/detected", value: TRUE);
set_kb_item(name: "cisco/small_business/snmp/port", value: port);
set_kb_item(name: "cisco/small_business/snmp/" + port + "/banner", value: sysdesc);

mod = eregmatch(pattern: "Cisco Small Business ([a-zA-z]+[^, ]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

vers = eregmatch(pattern: ", Version ([0-9]+[^ \r\n]+)", string: sysdesc, icase: TRUE);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "cisco/small_business/snmp/" + port + "/model", value: model);
set_kb_item(name: "cisco/small_business/snmp/" + port + "/version", value: version);

exit(0);

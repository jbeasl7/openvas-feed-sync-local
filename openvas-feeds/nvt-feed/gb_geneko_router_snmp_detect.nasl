# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107261");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-11-17 14:42:26 +0700 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Geneko Router Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Geneko routers.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);

if (!sysdesc)
  exit(0);

# Linux geneko 4.1.0-linux4sam_5.2-00047-g0bf8b22 #5 Fri May 10 08:52:13 CEST 2019 armv7l
# Linux geneko 3.18.21-geneko-linux4sam_4.7-rt19 #1 PREEMPT RT Wed Feb 10 10:05:39 CET 2016 armv7l
#
# Note: e.g. 4.1.0 is the Linux Kernel version, not the version of the router.
if ("Linux geneko" >< sysdesc) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "geneko/router/detected", value: TRUE);
  set_kb_item(name: "geneko/router/snmp/port", value: port);
  set_kb_item(name: "geneko/router/snmp/" + port + "/concluded", value: sysdesc);
  set_kb_item(name: "geneko/router/snmp/" + port + "/version", value: version);
  set_kb_item(name: "geneko/router/snmp/" + port + "/model", value: model);
}

exit(0);

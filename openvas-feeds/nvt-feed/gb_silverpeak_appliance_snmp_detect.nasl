# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141389");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-08-23 12:36:07 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Aruba / Silver Peak Appliance Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Aruba / Silver Peak appliances.");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

if (sysdesc !~ "Silver Peak Systems, Inc\. (EC|NX|VX)" || sysdesc !~ "(VXOA |ECOS)")
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "silverpeak/appliance/detected", value: TRUE);
set_kb_item(name: "silverpeak/appliance/snmp/detected", value: TRUE);
set_kb_item(name: "silverpeak/appliance/snmp/port", value: port);
set_kb_item(name: "silverpeak/appliance/snmp/" + port + "/concluded", value: sysdesc);

#Silver Peak Systems, Inc. ECV
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.8.0_71257 SMP Mon Jun 18 15:28:45 PDT 2018 x86_64
#
#Silver Peak Systems, Inc. ECXS
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.9.3_74197 SMP Tue Jan 29 16:46:04 PST 2019 x86_64
#
#Silver Peak Systems, Inc. ECXL
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.7.14_72871 SMP Thu Oct 11 01:20:43 PDT 2018 x86_64
#
#Silver Peak Systems, Inc. ECM
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.6.0_67090 SMP Fri Sep 15 17:35:59 PDT 2017 x86_64
#
#Silver Peak Systems, Inc. ECV
#Linux test-ECV01 4.19.87-sps #1 SMP PREEMPT Wed Sep 28 11:24:27 UTC 2022 ECOS 9.1.4.1_92329 #1-dev 2022-11-16 12:49:46 x86_64 sptest@yocto-app-build6:unknown
#
#Based on -> https://www.silver-peak.com/products/wan-optimization/nx-physical-appliances
#Silver Peak Systems, Inc. NX11k
#Linux ...
#
#Silver Peak Systems, Inc. NX5700
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.5.9_69125 SMP Wed Feb 28 14:54:46 PST 2018 x86_64
#
mod = eregmatch(pattern: "Silver Peak Systems, Inc. ((EC(V|XS|S|M|L|XL|US|[0-9]+))|NX[0-9]+k?|VX[0-9]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

vers = eregmatch(pattern: "VXOA ([0-9.]+)", string: sysdesc);
if (isnull(vers[1]))
  vers = eregmatch(pattern: "ECOS ([0-9.]+)", string: sysdesc);

if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "silverpeak/appliance/snmp/" + port + "/model", value: model);
set_kb_item(name: "silverpeak/appliance/snmp/" + port + "/version", value: version);

exit(0);

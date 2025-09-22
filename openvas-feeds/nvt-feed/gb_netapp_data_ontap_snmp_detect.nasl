# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140349");
  script_version("2025-06-16T05:41:07+0000");
  script_tag(name:"last_modification", value:"2025-06-16 05:41:07 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"creation_date", value:"2017-09-05 09:15:15 +0700 (Tue, 05 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of NetApp Data ONTAP.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default:161);

if(!sysdesc = snmp_get_sysdescr(port:port))
  exit(0);

if (sysdesc =~ "^NetApp Release") {
  set_kb_item(name: "netapp_data_ontap/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/snmp/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/snmp/port", value: port);
  set_kb_item(name: "netapp_data_ontap/snmp/" + port + "/concluded", value: sysdesc);

  vers = eregmatch(pattern: "NetApp Release ([0-9P.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "netapp_data_ontap/snmp/" + port + "/version", value: version);
  }
}

exit(0);

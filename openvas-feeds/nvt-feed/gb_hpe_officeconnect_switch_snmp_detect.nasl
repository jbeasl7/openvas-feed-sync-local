# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113257");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-08-30 09:54:55 +0200 (Thu, 30 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HPE OfficeConnect Switch Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of HPE OfficeConnect switches.");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port );

# HPE OfficeConnect Switch 1820 8G J9979A, PT.02.01, Linux 3.6.5-79c95a77, U-Boot 2012.10-00116-g3ab515c (Jul 30 2014 - 10:52:01)
# HPE OfficeConnect Switch 1920S 8G JL380A, PD.01.05, Linux 3.6.5-ac96795c, U-Boot 2012.10-00118-g3773021 (Oct 11 2016 - 15:39:54)
if (!sysdesc || sysdesc !~ "HP[E]?( OfficeConnect)?( Switch)? [0-9]{4}")
  exit(0);

version = "unknown";
model = "unknown";
series = "unknown";

set_kb_item(name: "hp/officeconnect/switch/detected", value: TRUE);
set_kb_item(name: "hp/officeconnect/switch/snmp/detected", value: TRUE);
set_kb_item(name: "hp/officeconnect/switch/snmp/port", value: port);
set_kb_item(name: "hp/officeconnect/switch/snmp/" + port + "/concluded", value: sysdesc);

mod = eregmatch(string: sysdesc, pattern: "HP[E]?( OfficeConnect)?( Switch)? ([0-9A-Z]+) [^ ]+ ([^,\r\n]+)", icase: TRUE);
if (!isnull(mod[3]))
  series = mod[3];

if (!isnull(mod[4]))
  model = mod[4];

vers = eregmatch(string: sysdesc, pattern: 'HP[E]?[^,]+,[ ]?[^0-9]*([0-9.]+)', icase: TRUE);
if (!isnull( vers[1]))
  version = vers[1];

set_kb_item(name: "hp/officeconnect/switch/snmp/" + port + "/version", value: version);
set_kb_item(name: "hp/officeconnect/switch/snmp/" + port + "/model", value: model);
set_kb_item(name: "hp/officeconnect/switch/snmp/" + port + "/series", value: series);

exit(0);

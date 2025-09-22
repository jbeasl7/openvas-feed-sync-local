# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170984");
  script_version("2024-11-29T15:40:53+0000");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-27 20:50:29 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axis Devices Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Axis devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
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

#; AXIS Q7404; Network Video Encoder; 5.51.7.6; Nov 23 2021 10:59; 165; 1;
#; AXIS Q1700-LE; License Plate Camera; 11.10.61; Apr 18 2024 18:26; 7C8; 1
# ; AXIS 207MW; Network Camera; 4.44; Mar 23 2009 13:20; 157; 1;
if (sysdesc !~ "^\s*; AXIS")
  exit(0);

set_kb_item(name: "axis/device/detected", value: TRUE);
set_kb_item(name: "axis/device/snmp/port", value: port);
set_kb_item(name: "axis/device/snmp/" + port + "/concluded", value: sysdesc);

model = "unknown";
version = "unknown";

mod = eregmatch(pattern: ";\s*AXIS ([^;]+); ([^;]+); ([.0-9]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

if (!isnull(mod[2])) {
  full_name = model + " " + mod[2];
  set_kb_item(name: "axis/device/snmp/" + port + "/modelName", value: full_name);
}

if (!isnull(mod[3]))
  version = mod[3];

set_kb_item(name: "axis/device/snmp/" + port + "/model", value: model);
set_kb_item(name: "axis/device/snmp/" + port + "/version", value: version);

exit(0);

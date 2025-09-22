# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149039");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2022-12-20 06:08:03 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SHARP Printer Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of SHARP printer devices.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# SHARP MX-M314N
# SHARP MX-5141N
# SHARP BP-70C31
if (sysdesc !~ "^SHARP ")
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "sharp/printer/detected", value: TRUE);
set_kb_item(name: "sharp/printer/snmp/detected", value: TRUE);
set_kb_item(name: "sharp/printer/snmp/port", value: port);
set_kb_item(name: "sharp/printer/snmp/" + port + "/banner", value: sysdesc);

mod = eregmatch(pattern: "^SHARP ([^ \r\n]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

fw_oid = "1.3.6.1.2.1.43.15.1.1.6.1.1";
vers = snmp_get(port: port, oid: fw_oid);
if (!isnull(vers) && vers != "") {
  fw_version = vers;
  set_kb_item(name: "sharp/printer/snmp/" + port + "/concludedFwOID", value: fw_oid);
}

set_kb_item(name: "sharp/printer/snmp/" + port + "/model", value: model);
set_kb_item(name: "sharp/printer/snmp/" + port + "/fw_version", value: fw_version);

exit(0);

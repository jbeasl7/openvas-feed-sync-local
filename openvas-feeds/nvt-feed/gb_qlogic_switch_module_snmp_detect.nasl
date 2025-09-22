# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141703");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-11-20 09:29:04 +0700 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QLogic Switch Module for IBM BladeCenter Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of QLogic Switch Module for IBM BladeCenter

  This script performs SNMP based detection of QLogic Switch Module for IBM BladeCenter.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# QLogic(R) 20-Port 4/8 Gb SAN Switch Module for IBM BladeCenter(R)
if (sysdesc =~ "QLogic.*Switch Module for IBM BladeCenter") {
  version = "unknown";

  mo = eregmatch(pattern: "QLogic[^ ]+ (.*) Switch", string: sysdesc);
  if (!isnull(mo[1]))
    model = mo[1];
  else
    exit(0);

  set_kb_item(name: "qlogic_switchmodule/detected", value: TRUE);
  set_kb_item(name: "qlogic_switchmodule/model", value: model);

  cpe = 'cpe:/h:qlogic:switch_module_firmware';

  register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "QLogic " + model + " Switch Module for IBM BladeCenter",
                                           version: version, install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: "udp");
  exit(0);
}

exit(0);

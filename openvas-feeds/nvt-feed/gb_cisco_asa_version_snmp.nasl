# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106513");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-01-12 15:23:14 +0700 (Thu, 12 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco ASA Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Cisco ASA.

  This script performs SNMP based detection of Cisco ASA.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc) exit(0);

if ("Cisco Adaptive Security Appliance" >< sysdesc) {
  version = "unknown";
  model = "unknown";

  vers = eregmatch(pattern: "Cisco Adaptive Security Appliance Version ([^ \r\n]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "cisco_asa/version", value: version);
  }

  mod = snmp_get(port: port, oid: '1.3.6.1.2.1.47.1.1.1.1.13.1');
  if(!isnull(mod))
  {
    model = str_replace(string: mod, find: '"', replace: "");
    set_kb_item(name: "cisco_asa/model", value: model);
  }

  set_kb_item(name: "cisco_asa/detected", value: TRUE);

  # For the application
  cpe = build_cpe(value: version, exp: "^([0-9.()]+)", base: "cpe:/a:cisco:asa:");
  if (!cpe)
    cpe = 'cpe:/a:cisco:asa';

  # For the OS
  cpe2 = build_cpe(value: version, exp: "^([0-9.()]+)", base: "cpe:/o:cisco:adaptive_security_appliance_software:");
  if (!cpe2)
    cpe2 = 'cpe:/o:cisco:adaptive_security_appliance_software';

  register_product(cpe: cpe, location:port + "/udp", proto:"udp", service:"snmp" );
  os_register_and_report(os: "Cisco ASA", cpe: cpe2, banner_type: "SNMP sysdesc", banner: sysdesc, port: port,
                         proto: "udp", desc: "Cisco ASA Detection (SNMP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Cisco ASA", version: version, install: "161/udp", cpe: cpe,
                                           concluded: sysdesc, extra: "Model: " + model),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106494");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-01-05 14:24:16 +0700 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Arista EOS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Arista EOS devices.");

  script_xref(name:"URL", value:"https://www.arista.com/en/products/eos");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc)
  exit(0);

if ("Arista Networks EOS" >< sysdesc) {
  model = "unknown";
  version = "unknown";
  location = "/";

  mod = eregmatch(pattern: "running on an Arista Networks ([0-9A-Z-]+)", string: sysdesc);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "arista/eos/model", value: model);
  }

  vers = eregmatch(pattern: "EOS version ([0-9A-Z.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "arista/eos/detected", value: TRUE);
  set_kb_item(name: "arista/eos/snmp/detected", value: TRUE);

  os_cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.]+)", base: "cpe:/o:arista:eos:");
  if (!os_cpe)
    os_cpe = "cpe:/o:arista:eos";

  if (model != "unknown") {
    hw_name = "Arista " + model;
    hw_cpe = "cpe:/h:arista:" + tolower(model);
  } else {
    hw_name = "Arista Switch Unknown Model";
    hw_cpe = "cpe:/h:arista:switch";
  }

  register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");

  os_register_and_report(os: "Arista EOS", cpe: os_cpe, banner_type: "SNMP sysdesc", banner: sysdesc, port: port,
                         proto: "udp", desc: "Arista EOS Detection (SNMP)", runs_key: "unixoide");

  report  = build_detection_report(app: "Arista EOS", version: version, install: location, cpe: os_cpe,
                                   concluded: sysdesc);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

  log_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(0);

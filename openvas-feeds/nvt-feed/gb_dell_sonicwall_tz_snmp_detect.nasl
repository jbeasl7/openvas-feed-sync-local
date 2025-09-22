# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106569");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SonicWall/Dell SonicWALL TZ Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of SonicWall (formerly Dell SonicWALL) TZ devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_xref(name:"URL", value:"https://www.sonicwall.com/products/firewalls/entry-level/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");
include("os_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc)
  exit(0);

# SonicWALL TZ 300 (SonicOS Enhanced 6.5.1.1-42n)
# SonicWALL TZ 370 (SonicOS 7.0.1-5051-R2624)
if ("SonicWALL TZ" >< sysdesc) {
  version = "unknown";

  mod = eregmatch(pattern: "SonicWALL TZ ([0-9]+)", string: sysdesc);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "sonicwall/tz/model", value: model);

  vers = eregmatch(pattern: "SonicOS( Enhanced)? ([^)]+)", string: sysdesc);
  if (!isnull(vers[2]))
    version =  vers[2];

  set_kb_item(name: "sonicwall/tz/detected", value: TRUE);
  set_kb_item(name: "sonicwall/tz/snmp/detected", value: TRUE);

  os_cpe1 = build_cpe(value: tolower(version), exp: "^([0-9a-z.-]+)",
                      base: "cpe:/o:sonicwall:sonicos:");
  os_cpe2 = build_cpe(value: tolower(version), exp: "^([0-9a-z.-]+)",
                      base: "cpe:/o:dell:sonicwall_totalsecure_tz_" + model + "_firmware:");
  if (!os_cpe1) {
    os_cpe1 = "cpe:/o:sonicwall:sonicos";
    os_cpe2 = "cpe:/o:dell:sonicwall_totalsecure_tz_" + model + "_firmware";
  }

  hw_cpe = "cpe:/h:sonicwall:tz" + model;

  os_register_and_report(os: "SonicWall/Dell SonicWALL SonicOS", cpe: os_cpe1, runs_key: "unixoide",
                         desc: "SonicWall/Dell SonicWALL TZ Detection (SNMP)");

  register_product(cpe: os_cpe1, port: port, location: "/", service: "snmp", proto: "udp");
  register_product(cpe: os_cpe2, port: port, location: "/", service: "snmp", proto: "udp");
  register_product(cpe: hw_cpe, port: port, location: "/", service: "snmp", proto: "udp");

  report = build_detection_report(app: "SonicWall/Dell SonicWALL SonicOS", version: version, install: "/", cpe: os_cpe1,
                                  concluded: sysdesc);
  report += '\n\n';
  report += build_detection_report(app: "SonicWall/Dell SonicWALL TZ " + model, skip_version: TRUE, install: "/",
                                   cpe: hw_cpe);

  log_message(data: report, port: port, proto: "udp");
  exit(0);
}

exit(0);

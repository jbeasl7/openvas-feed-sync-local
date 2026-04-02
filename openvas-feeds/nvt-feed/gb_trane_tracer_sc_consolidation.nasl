# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156589");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"creation_date", value:"2026-03-23 09:52:22 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trane Tracer SC / SC+ Devices Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_trane_tracer_sc_bacnet_detect.nasl",
                      "gb_trane_tracer_sc_http_detect.nasl");
  script_mandatory_keys("trane/tracer/sc_or_sc_plus/detected");

  script_tag(name:"summary", value:"Consolidation of Trane Tracer SC / SC+ Devices detections.");

  script_xref(name:"URL", value:"https://www.trane.com/commercial/north-america/us/en/products-systems/smart-building-technology/building-controls-solutions/tracer-sc-plus.html");
  script_xref(name:"URL", value:"https://www.trane.com/commercial/north-america/us/en/controls/building-Management/tracer-sc.html");

  exit(0);
}

if (!get_kb_item("trane/tracer/sc_or_sc_plus/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

if (get_kb_item("trane/tracer/sc/detected")) {
  base_kb = "trane/tracer/sc";
  os_name = "Trane Tracer SC Firmware";
  hw_name = "Trane Tracer SC";
  base_os_cpe = "cpe:/o:trane:tracer_sc_firmware";
  hw_cpe = "cpe:/h:trane:tracer_sc";
} else {
  base_kb = "trane/tracer/sc_plus";
  os_name = "Trane Tracer SC+ Firmware";
  hw_name = "Trane Tracer SC+";
  base_os_cpe = "cpe:/o:trane:tracer_sc%2b_firmware";
  hw_cpe = "cpe:/h:trane:tracer_sc%2b";
}

foreach source (make_list("bacnet", "http")) {
  version_list = get_kb_list(base_kb + "/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: base_os_cpe + ":");
if (!os_cpe)
  os_cpe = base_os_cpe;

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Trane Tracer SC / SC+ Devices Detection Consolidation");

if (http_ports = get_kb_list(base_kb + "/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item(base_kb + "/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item(base_kb + "/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (bacnet_ports = get_kb_list(base_kb + "/bacnet/port")) {
  foreach port (bacnet_ports) {
    extra += "BACnet on port " + port + '/udp\n';

    concluded = get_kb_item(base_kb + "/bacnet/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "bacnet", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "bacnet", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location,
                                 cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

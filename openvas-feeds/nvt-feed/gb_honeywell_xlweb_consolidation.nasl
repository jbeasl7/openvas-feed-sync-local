# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144491");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-08-27 08:29:48 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Honeywell Excel Web Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Honeywell Excel Web detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_honeywell_xlweb_bacnet_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_honeywell_xlweb_ftp_detect.nasl", "gsf/gb_honeywell_xlweb_telnet_detect.nasl",
                        "gsf/gb_honeywell_xlweb_http_detect.nasl");
  script_mandatory_keys("honeywell/excel_web/detected");

  script_xref(name:"URL", value:"https://www.honeywell.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("honeywell/excel_web/detected"))
  exit(0);

detected_version = "unknown";
location = "/";
os_name = "Honeywell Excel Web Controller Firmware";
hw_name = "Honeywell Excel Web Controller";

foreach source (make_list("bacnet")) {
  version_list = get_kb_list("honeywell/excel_web/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:honeywell:xl_web_ii_controller:");
if (!os_cpe)
  os_cpe = "cpe:/o:honeywell:xl_web_ii_controller";

hw_cpe = "cpe:/h:honeywell:xl_web_ii_controller";

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Honeywell Excel Web Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("honeywell/excel_web/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concUrl= get_kb_item("honeywell/excel_web/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (ftp_ports = get_kb_list("honeywell/excel_web/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port ' + port + '/tcp\n';
    concluded = get_kb_item("honeywell/excel_web/ftp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from FTP banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ftp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ftp");
  }
}

if (bacnet_ports = get_kb_list("honeywell/excel_web/bacnet/port")) {
  foreach port (bacnet_ports) {
    extra += 'BACnet on port ' + port + '/udp\n';
    concluded = get_kb_item("honeywell/excel_web/bacnet/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "bacnet", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "bacnet", proto: "udp");
  }
}

if (telnet_ports = get_kb_list("honeywell/excel_web/telnet/port")) {
  foreach port (telnet_ports) {
    extra += 'Telnet on port ' + port + '/tcp\n';
    concluded = get_kb_item("honeywell/excel_web/telnet/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from Telnet banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);

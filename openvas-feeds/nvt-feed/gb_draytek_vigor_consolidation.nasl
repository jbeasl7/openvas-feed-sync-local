# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143663");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-03-31 09:10:05 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of DrayTek Vigor device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_draytek_vigor_http_detect.nasl", "gb_draytek_vigor_snmp_detect.nasl",
                      "gb_draytek_vigor_pptp_detect.nasl", "gb_draytek_vigor_ftp_detect.nasl",
                      "gb_draytek_vigor_telnet_detect.nasl");
  script_mandatory_keys("draytek/vigor/detected");

  script_xref(name:"URL", value:"https://www.draytek.com/products/");

  exit(0);
}

if (!get_kb_item("draytek/vigor/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
os_name = "DrayTek Vigor ";
hw_name = os_name;
location = "/";

foreach source (make_list("snmp", "http", "pptp", "ftp", "telnet")) {
  model_list = get_kb_list("draytek/vigor/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("draytek/vigor/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  if (detected_version != "unknown" && detected_model != "unknown")
    break;
}

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;
  cpe_model = str_replace(string: tolower(model), find: " ", replace: "_");
  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([a-z0-9._]+)",
                     base: "cpe:/o:draytek:vigor" + cpe_model + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:draytek:vigor" + cpe_model + "_firmware";

  hw_cpe = "cpe:/h:draytek:vigor" + cpe_model;
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([a-z0-9._]+)", base: "cpe:/o:draytek:vigor_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:draytek:vigor_firmware";

  hw_cpe = "cpe:/h:draytek:vigor";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "DrayTek Vigor Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("draytek/vigor/http/port")) {
  foreach port (http_ports) {
    extra += "- HTTP(s) on port " + port + '/tcp\n';
    concluded = get_kb_item("draytek/vigor/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    concUrl = get_kb_item("draytek/vigor/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("draytek/vigor/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "- SNMP on port " + port + '/udp\n';
    concluded = get_kb_item("draytek/vigor/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from SNMP sysDescr OID: " + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (pptp_ports = get_kb_list("draytek/vigor/pptp/port")) {
  foreach port (pptp_ports) {
    extra += "- PPTP on port " + port + '/tcp\n';
    concluded = get_kb_item("draytek/vigor/pptp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from PPTP banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "pptp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "pptp");
  }
}

if (ftp_ports = get_kb_list("draytek/vigor/ftp/port")) {
  foreach port (ftp_ports) {
    extra += "- FTP on port " + port + '/tcp\n';
    concluded = get_kb_item("draytek/vigor/ftp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from FTP banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ftp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ftp");
  }
}

if (telnet_ports = get_kb_list("draytek/vigor/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "- Telnet on port " + port + '/tcp\n';
    concluded = get_kb_item("draytek/vigor/telnet/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from Telnet banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp( extra );
}

log_message(port: 0, data: report);

exit(0);

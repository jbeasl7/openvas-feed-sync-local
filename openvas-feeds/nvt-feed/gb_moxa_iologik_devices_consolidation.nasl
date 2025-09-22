# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143571");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-03-03 04:24:24 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa ioLogik Device Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Moxa ioLogik device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_moxa_iologik_devices_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_moxa_iologik_devices_snmp_detect.nasl");
  script_mandatory_keys("moxa/iologik/detected");

  script_xref(name:"URL", value:"https://www.moxa.com/en/products/industrial-edge-connectivity/controllers-and-ios/universal-controllers-and-i-os");

  exit(0);
}

if (!get_kb_item("moxa/iologik/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("http", "snmp")) {
  version_list = get_kb_list("moxa/iologik/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("moxa/iologik/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  build_list = get_kb_list("moxa/iologik/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      build_info = "Build: " + detected_build;
      break;
    }
  }
}

os_name = "Moxa ioLogik ";
hw_name = os_name;

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:moxa:iologik_" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:iologik_" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:moxa:iologik_" + tolower(detected_model);
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:moxa:iologik_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:iologik_firmware";

  hw_cpe = "cpe:/h:moxa:iologik";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Moxa ioLogik Device Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("moxa/iologik/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("moxa/iologik/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("moxa/iologik/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("moxa/iologik/snmp/" + port + "/concluded");
    concludedOID = get_kb_item("moxa/iologik/snmp/" + port + "/concludedOID");
    if (concluded && concludedOID)
      extra += '  Concluded from ' + concluded + ' via OID: ' + concludedOID;

    register_product(cpe: hw_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe,
                                 extra: build_info);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);

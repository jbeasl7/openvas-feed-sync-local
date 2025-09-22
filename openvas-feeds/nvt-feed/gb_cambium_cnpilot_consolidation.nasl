# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140631");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cambium_cnpilot_http_detect.nasl",
                      "gb_cambium_cnpilot_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cambium_cnpilot_telnet_detect.nasl");
  script_mandatory_keys("cambium/cnpilot/detected");

  script_tag(name:"summary", value:"Consolidation of Cambium Networks cnPilot detections.");

  script_xref(name:"URL", value:"https://www.cambiumnetworks.com/products/wifi/");

  exit(0);
}

if (!get_kb_item("cambium/cnpilot/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_fw_version = "unknown";
detected_model = "unknown";
location = "/";
hw_name = "Cambium Networks cnPilot";

foreach source (make_list("http", "snmp", "telnet")) {
  fw_version_list = get_kb_list("cambium/cnpilot/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      break;
    }
  }

  model_list = get_kb_list("cambium/cnpilot/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cambium/cnpilot/model", value: model);
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = hw_name + " " + detected_model + " Firmware";
  hw_name += " " + detected_model;

  os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9r.-]+)",
                     base: "cpe:/o:cambiumnetworks:cnpilot_" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:cambiumnetworks:cnpilot_" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:cambiumnetworks:cnpilot_" + tolower(detected_model);
} else {
  os_name = hw_name + " Unknown Model Firmware";
  hw_name += " Unknown Model";

  os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9r.-]+)",
                     base: "cpe:/o:cambiumnetworks:cnpilot_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:cambiumnetworks:cnpilot_firmware";

  hw_cpe = "cpe:/h:cambiumnetworks:cnpilot";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Cambium Networks cnPilot Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("cambium/cnpilot/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("cambium/cnpilot/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("cambium/cnpilot/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("cambium/cnpilot/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("cambium/cnpilot/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (telnet_ports = get_kb_list("cambium/cnpilot/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "Telnet on port " + port + '/tcp\n';

    concluded = get_kb_item("cambium/cnpilot/telnet/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report = build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

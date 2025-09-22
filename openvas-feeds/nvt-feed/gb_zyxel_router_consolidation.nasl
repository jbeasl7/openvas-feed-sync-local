# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153896");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-30 03:48:09 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zyxel Router / Gateway Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_zyxel_router_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_zyxel_router_snmp_detect.nasl",
                        "gsf/gb_zyxel_router_telnet_detect.nasl");
  script_mandatory_keys("zyxel/router/detected");

  script_tag(name:"summary", value:"Consolidation of Zyxel Router / Gateway devices detections.");

  script_xref(name:"URL", value:"https://www.zyxel.com/global/en/products/dsl-cpe");

  exit(0);
}

if (!get_kb_item("zyxel/router/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("snmp", "http", "telnet")) {
  model_list = get_kb_list("zyxel/router/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("zyxel/router/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Zyxel " + detected_model + " Firmware";
  hw_name = "Zyxel " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "([0-9a-zA-Z\(\).]+)",
                     base: "cpe:/o:zyxel:" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:zyxel:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:zyxel:" + tolower(detected_model);
} else {
  os_name = "Zyxel Router / Gateway Firmware";
  hw_name = "Zyxel Router / Gateway Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9a-zA-Z\(\).]+)",
                     base: "cpe:/o:zyxel:router_firmware:");
  if (!cpe)
    os_cpe = "cpe:/o:zyxel:router_firmware";

  hw_cpe = "cpe:/h:zyxel:router";
}

os_register_and_report(os: os_name , cpe: os_cpe, runs_key: "unixoide",
                       desc: "Zyxel Router / Gateway Detection Consolidation");

if (http_ports = get_kb_list("zyxel/router/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("zyxel/router/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("zyxel/router/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("zyxel/router/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    conclMod = get_kb_item("zyxel/router/snmp/" + port + "/concludedMod");
    conclModOID = get_kb_item("zyxel/router/snmp/" + port + "/concludedModOID");
    if (conclMod && conclModOID)
      extra += "  Model concluded from '" + conclMod + "' via OID: " + conclModOID + '\n';

    conclVers = get_kb_item("zyxel/router/snmp/" + port + "/concludedVers");
    conclVersOID = get_kb_item("zyxel/router/snmp/" + port + "/concludedVersOID");
    if (conclVers && conclVersOID)
      extra += "  Version concluded from '" + conclVers + "' via OID: " + conclVersOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (telnet_ports = get_kb_list("zyxel/router/telnet/port")) {
  foreach port (telnet_ports) {
    extra += "Telnet on port " + port + '/tcp\n';

    concluded = get_kb_item("zyxel/router/telnet/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

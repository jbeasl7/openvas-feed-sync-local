# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151840");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-02-27 04:01:04 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa EDS Device Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_moxa_eds_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_moxa_eds_snmp_detect.nasl");
  script_mandatory_keys("moxa/eds/detected");

  script_tag(name:"summary", value:"Consolidation of Moxa EDS device detections.");

  script_xref(name:"URL", value:"https://www.moxa.com/en/products/industrial-network-infrastructure/ethernet-switches");

  exit(0);
}

if (!get_kb_item("moxa/eds/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("snmp", "http")) {
  model_list = get_kb_list("moxa/eds/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "moxa/eds/model", value: model);
      break;
    }
  }

  version_list = get_kb_list("moxa/eds/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Moxa " + detected_model + " Firmware";
  hw_name = "Moxa " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:moxa:" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:moxa:" + tolower(detected_model);
} else {
  os_name = "Moxa EDS Firmware";
  hw_name = "Moxa EDS Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:moxa:eds_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:eds_firmware";

  hw_cpe = "cpe:/h:moxa:eds_switch";
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Moxa EDS Device Detection Consolidation");

if (http_ports = get_kb_list("moxa/eds/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("moxa/eds/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("moxa/eds/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    mac = get_kb_item("moxa/eds/http/" + port + "/mac");
    if (mac)
      macaddr = "MAC address:    " + mac;

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("moxa/eds/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    conclMod = get_kb_item("moxa/eds/snmp/" + port + "/concludedMod");
    conclModOID = get_kb_item("moxa/eds/snmp/" + port + "/concludedModOID");
    if (conclMod && conclModOID)
      extra += "  Model concluded from '" + conclMod + "' via OID: " + conclModOID + '\n';

    conclVers = get_kb_item("moxa/eds/snmp/" + port + "/concludedVers");
    conclVersOID = get_kb_item("moxa/eds/snmp/" + port + "/concludedVersOID");
    if (conclVers && conclVersOID)
      extra += "  Version concluded from '" + conclVers + "' via OID: " + conclVersOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe,
                                 extra: macaddr);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);

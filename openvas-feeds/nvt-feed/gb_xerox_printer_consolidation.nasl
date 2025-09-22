# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141824");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-01-04 13:08:39 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Xerox Printer Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Xerox printer detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_xerox_printer_http_detect.nasl", "gb_xerox_printer_snmp_detect.nasl",
                      "gb_xerox_printer_pjl_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_xref(name:"URL", value:"https://www.xerox.com/en-us/printing-equipment");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("xerox_printers.inc");

if (!get_kb_item("xerox/printer/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";

# nb: Found cases where model collected via HTTP was more exact that the model collected via SNMP
# eg. Xerox WorkCentre 6515DN via HTTP and WorkCentre 6515 via SNMP
foreach source (make_list("http", "snmp", "hp-pjl")) {
  fw_version_list = get_kb_list("xerox/printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "xerox/printer/fw_version", value: fw_version);
      break;
    }
  }

  model_list = get_kb_list("xerox/printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "xerox/printer/model", value: model);
      break;
    }
  }
}

os_name = "Xerox Printer ";
if (detected_model != "unknown") {
  # nb: Sometimes the model includes a trailing space from the SNMP detection, just get rid of this
  # here. Note that we don't want to do that directly in the SNMP detection because it is currently
  # unclear how the build_xerox_cpe() is handling such a missing space.
  os_name += chomp(detected_model) + " Firmware";
  hw_name += chomp(detected_model);
  hw_cpe = build_xerox_cpe(model: detected_model);
  os_cpe = str_replace(string: hw_cpe, find: "cpe:/h", replace: "cpe:/o");
  os_cpe += "_firmware";
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";
  hw_cpe = "cpe:/h:xerox:printer";
  os_cpe = "cpe:/o:xerox:printer_firmware";
}

if (detected_fw_version != "unknown")
  os_cpe += ':' + detected_fw_version;

location = "/";

if (http_ports = get_kb_list("xerox/printer/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("xerox/printer/http/" + port + "/concluded");
    concUrl = get_kb_item("xerox/printer/http/" + port + "/concludedUrl");

    extra += "HTTP(s) on port " + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';
    if (concUrl)
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("xerox/printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item('xerox/printer/snmp/' + port + '/concluded');
    if (concluded)
      extra += '  Concluded from SNMP sysDescr OID: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (pjl_ports = get_kb_list("xerox/printer/hp-pjl/port")) {
  foreach port (pjl_ports) {
    extra += 'PJL on port ' + port + '/tcp\n';

    concluded = get_kb_item("xerox/printer/hp-pjl/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from PJL banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: location, port: port, service: "hp-pjl");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Xerox Printer Detection Consolidation", runs_key: "unixoide");

report += build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

pref = get_kb_item("global_settings/exclude_printers");
if (pref == "yes") {
  log_message(port: 0, data: 'The remote host is a printer. The scan has been disabled against this host.\n' +
                             'If you want to scan the remote host, uncheck the "Exclude printers from scan" ' +
                             'option and re-scan it.');
  set_kb_item(name: "Host/dead", value: TRUE);
}

exit(0);

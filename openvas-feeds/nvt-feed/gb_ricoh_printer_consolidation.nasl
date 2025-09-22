# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142807");
  script_version("2025-05-23T15:42:02+0000");
  script_tag(name:"last_modification", value:"2025-05-23 15:42:02 +0000 (Fri, 23 May 2025)");
  script_tag(name:"creation_date", value:"2019-08-27 09:14:25 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of RICOH Printer device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_ricoh_printer_snmp_detect.nasl", "gb_ricoh_printer_ftp_detect.nasl",
                      "gb_ricoh_printer_http_detect.nasl", "gb_ricoh_printer_pjl_detect.nasl",
                      "global_settings.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_xref(name:"URL", value:"https://www.ricoh.com/products/printers-and-copiers/");
  script_xref(name:"URL", value:"https://wizixtech.com/ricoh-savin-lanier-merge/");
  script_xref(name:"URL", value:"http://support.ricoh.com/html_gen/util/PDE/Model_PDE.html#inf");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("ricoh/printer/detected"))
  exit(0);

detected_model = "unknown";
detected_brand = "unknown";
detected_fw_version = "unknown";
detected_web_version = "unknown";

foreach source (make_list("http", "snmp", "ftp", "hp-pjl")) {
  fw_version_list = get_kb_list("ricoh/printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "ricoh/printer/fw_version", value: fw_version);
      break;
    }
  }

  model_list = get_kb_list("ricoh/printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "ricoh/printer/model", value: model);
      break;
    }
  }

  brand_list = get_kb_list("ricoh/printer/" + source + "/*/brand");
  foreach brand (brand_list) {
    if (brand != "unknown" && detected_brand == "unknown") {
      detected_brand = brand;
      set_kb_item(name: "ricoh/printer/brand", value: brand);
      break;
    }
  }

  web_version_list = get_kb_list("ricoh/printer/" + source + "/*/web_version");
  foreach web_version (web_version_list) {
    if (web_version != "unknown" && detected_web_version == "unknown") {
      detected_web_version = web_version;
      set_kb_item(name: "ricoh/printer/web_version", value: web_version);
      break;
    }
  }
}

product_name = detected_brand;

if (detected_brand == "unknown") {
  detected_brand = "RICOH";
  product_name = detected_brand;
} else if (detected_brand != "RICOH")
  product_name = detected_brand + " (RICOH Subsidiary)";

os_name = product_name + " Printer ";
hw_name = os_name;
if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;
  cpe_model = tolower(str_replace(string: detected_model, find: " ", replace: "_"));
  hw_cpe = "cpe:/h:ricoh:" + cpe_model;
  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)_?([a-z0-9]+)?",
                       base: "cpe:/o:ricoh:" + cpe_model + "_firmware:");
  else
    os_cpe = "cpe:/o:ricoh:" + cpe_model + "_firmware";
} else {
  os_name = product_name + " Printer Unknown Model Firmware";
  hw_name = product_name + " Printer Unknown Model";
  hw_cpe = "cpe:/h:ricoh:printer";
  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: detected_fw_version, exp: "^([0-9.]+)", base: "cpe:/o:ricoh:printer_firmware:");
  else
    os_cpe = "cpe:/o:ricoh:printer_firmware";
}

location = "/";

if (http_ports = get_kb_list("ricoh/printer/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item('ricoh/printer/http/' + port + '/concluded');
    if (concluded) {
      concUrl = get_kb_item('ricoh/printer/http/' + port + '/concludedUrl');
      if (concUrl)
        extra += '  Concluded from version/product identification location: ' +
                 concUrl + '\n';

      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("ricoh/printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item('ricoh/printer/snmp/' + port + '/concluded');
    if (concluded)
      extra += '  Concluded from SNMP sysDescr OID: ' + concluded + '\n';

    concludedFwOID = get_kb_item("ricoh/printer/snmp/" + port + "/concludedFwOID");
    if (concludedFwOID)
      extra += "  Version concluded via OID: " + concludedFwOID + '\n';

    register_product(cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
  }
}

if (ftp_ports = get_kb_list("ricoh/printer/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port ' + port + '/tcp\n';

    concluded = get_kb_item('ricoh/printer/ftp/' + port + '/concluded');
    if (concluded)
      extra += '  Concluded from FTP banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "ftp");
    register_product(cpe: hw_cpe, location: port + "/tcp", port: port, service: "ftp");
  }
}

if (pjl_ports = get_kb_list("ricoh/printer/hp-pjl/port")) {
  foreach port (pjl_ports) {
    extra += 'PJL on port ' + port + '/tcp\n';

    concluded = get_kb_item('ricoh/printer/hp-pjl/' + port + '/concluded');
    if (concluded)
      extra += '  Concluded from PJL banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: port + "/tcp", port: port, service: "hp-pjl");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe,
                       desc: "RICOH Printer Detection Consolidation", runs_key: "unixoide");

report  = build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

pref = get_kb_item("global_settings/exclude_printers");
if (pref == "yes") {
  log_message(port: 0, data: 'The remote host is a printer. The scan has been disabled against this host.\n' +
                             'If you want to scan the remote host, uncheck the "Exclude printers from scan" ' +
                             'option and re-scan it.');
  set_kb_item(name:"Host/dead", value:TRUE);
}

exit(0);

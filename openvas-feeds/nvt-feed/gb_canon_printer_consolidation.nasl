# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147494");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"creation_date", value:"2022-01-20 09:41:25 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Canon Printer Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Canon Printer device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_canon_printer_snmp_detect.nasl",
                      "gb_canon_printer_pjl_detect.nasl",
                      "gb_canon_printer_http_detect.nasl",
                      "gb_canon_printer_ipp_detect.nasl",
                      "global_settings.nasl");
  script_mandatory_keys("canon/printer/detected");

  script_xref(name:"URL", value:"https://www.usa.canon.com/internet/portal/us/home/products/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("canon/printer/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";
location = "/";

foreach source (make_list("http", "snmp", "hp-pjl", "ipp")) {
  model_list = get_kb_list("canon/printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      if (detected_model =~ "^i(mage)?R(UNNER)?") {
        mod = eregmatch(pattern: "^(i(mage)?R(UNNER)?(-ADV )?)(.*)", string: detected_model);
        if (!isnull(mod[5])) {
          prefix = "imageRUNNER ";
          if (mod[5] =~ "^ ")
            prefix = "imageRUNNER";
          detected_model = prefix + mod[5];
        }
      }
      if (detected_model =~ "^iPR ") {
        detected_model = str_replace(string: detected_model, find: "iPR", replace: "imagePRESS");
      }
      break;
    }
  }

  fw_version_list = get_kb_list("canon/printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version != "unknown" && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      break;
    }
  }
}

os_name = "Canon Printer ";
hw_name = os_name;

if (detected_model != "unknown") {
  if (detected_model =~ " Series$")
    detected_model = ereg_replace(string: detected_model, pattern: "( [Ss]eries)", replace: "");
  os_name += detected_model + " Firmware";
  hw_name += detected_model;
  cpe_model = str_replace(string: tolower(detected_model), find: " ", replace: "_");
  cpe_model = str_replace(string: cpe_model, find: "/", replace: "_");

  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:canon:" + cpe_model + "_firmware:");
  else
    os_cpe = "cpe:/o:canon:" + cpe_model + "_firmware";

  hw_cpe = "cpe:/h:canon:" + cpe_model;
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  if (detected_fw_version != "unknown")
    os_cpe = build_cpe(value: tolower(detected_fw_version), exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:canon:printer_firmware:");
  else
    os_cpe = "cpe:/o:canon:printer_firmware";

  hw_cpe = "cpe:/h:canon:printer";
}

if (http_ports = get_kb_list("canon/printer/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    modConcluded = get_kb_item("canon/printer/http/" + port + "/modConcluded");
    modConcludedUrl = get_kb_item("canon/printer/http/" + port + "/modConcludedUrl");
    versConcluded = get_kb_item("canon/printer/http/" + port + "/versConcluded");
    versConcludedUrl = get_kb_item("canon/printer/http/" + port + "/versConcludedUrl");
    if ((modConcluded && modConcludedUrl) || (versConcluded && versConcludedUrl)) {
      if (modConcluded)
        extra += '  Model concluded:\n    ' + chomp(modConcluded) + '\n  from URL:\n    ' + modConcludedUrl + '\n';

      if (versConcluded)
        extra += '  Version concluded:\n    ' + chomp(versConcluded) + '\n  from URL:\n    ' + versConcludedUrl + '\n';
    }

    generalConcluded = get_kb_item("canon/printer/http/" + port + "/generalConcluded");
    if (generalConcluded) {
      extra += '  Concluded from product identification result:\n';
      extra += '    HTTP banner: ' + generalConcluded + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("canon/printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concludedMod = get_kb_item("canon/printer/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("canon/printer/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Model concluded from "' + concludedMod + '" via OID: ' + concludedModOID + '\n';

    concludedFwOID = get_kb_item("canon/printer/snmp/" + port + "/concludedFwOID");
    if (concludedFwOID)
      extra += '  Version concluded via OID: ' + concludedFwOID + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (pjl_ports = get_kb_list("canon/printer/hp-pjl/port")) {
  foreach port (pjl_ports) {
    extra += 'PJL on port ' + port + '/tcp\n';

    concluded = get_kb_item("canon/printer/hp-pjl/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from PJL banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "hp-pjl");
    register_product(cpe: hw_cpe, location: location, port: port, service: "hp-pjl");
  }
}

if (ipp_ports = get_kb_list("canon/printer/ipp/port")) {
  foreach port (ipp_ports) {
    extra += 'IPP on port ' + port + '/tcp\n';

    concluded = get_kb_item("canon/printer/ipp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from IPP info:\n' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ipp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ipp");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Canon Printer Detection Consolidation");

report  = build_detection_report(app: os_name, version: detected_fw_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

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

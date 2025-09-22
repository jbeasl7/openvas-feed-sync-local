# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144339");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-07-31 06:23:21 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco ATA Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Cisco Analog Telephone Adapter (ATA) detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_ata_http_detect.nasl", "gb_cisco_ata_sip_detect.nasl");
  script_mandatory_keys("cisco/ata/detected");

  script_xref(name:"URL", value:"https://www.cisco.com");

  exit(0);
}

if (!get_kb_item("cisco/ata/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("http", "sip")) {
  version_list = get_kb_list("cisco/ata/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("cisco/ata/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/ata/model", value: detected_model);
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Cisco ATA " + detected_model + " Analog Telephone Adapter Firmware";
  hw_name = "Cisco ATA " + detected_model + " Analog Telephone Adapter";

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9a-z.]+)",
                     base: "cpe:/o:cisco:ata_" + detected_model + "_analog_telephone_adapter_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:cisco:ata_" + detected_model + "_analog_telephone_adapter_firmware";

  hw_cpe = "cpe:/h:cisco:ata_" + detected_model + "_analog_telephone_adapter";
} else {
  os_name = "Cisco ATA Unknown Model Analog Telephone Adapter Firmware";
  hw_name = "Cisco ATA Unknown Model Analog Telephone Adapter";

  os_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9a-z.]+)",
                     base: "cpe:/o:cisco:ata_analog_telephone_adapter_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:cisco:ata_analog_telephone_adapter_firmware";

  hw_cpe = "cpe:/h:cisco:ata_analog_telephone_adapter";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Cisco ATA Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("cisco/ata/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/ata/http/" + port + "/concluded");
    concUrl = get_kb_item("cisco/ata/http/" + port + "/concludedUrl");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "www");
    register_product(cpe: hw_cpe, location: port + "/tcp", port: port, service: "www");
  }
}

if (sip_ports = get_kb_list("cisco/ata/sip/port")) {
  foreach port (sip_ports) {
    proto = get_kb_item("cisco/ata/sip/" + port + "/proto");
    extra += 'SIP on port ' + port + '/' + proto + '\n';
    concluded = get_kb_item("cisco/ata/sip/" + port + "/concluded");
    if (concluded)
      extra += '  SIP Banner: ' + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "sip", proto: proto);
    register_product(cpe: os_cpe, location: location, port: port, service: "sip", proto: proto);
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

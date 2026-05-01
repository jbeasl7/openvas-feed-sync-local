# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140143");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell PowerProtect Data Domain Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_dell_powerprotect_data_domain_http_detect.nasl",
                      "gb_dell_powerprotect_data_domain_snmp_detect.nasl",
                      "gb_dell_powerprotect_data_domain_ssh_login_detect.nasl");
  script_mandatory_keys("dell/powerprotect/data_domain/detected");

  script_tag(name:"summary", value:"Consolidation of Dell PowerProtect Data Domain detections.");

  script_xref(name:"URL", value:"https://www.dell.com/en-us/shop/storage-servers-and-networking-for-business/sf/powerprotect-data-domain");

  exit(0);
}

if (!get_kb_item("dell/powerprotect/data_domain/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("dell/powerprotect/data_domain/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("dell/powerprotect/data_domain/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "dell/powerprotect/data_domain/model", value: detected_model);
      break;
    }
  }
}

app_name = "Dell PowerProtect Data Domain";

if (detected_model != "unknown")
  app_name += " on " + detected_model;

cpe = build_cpe(value: detected_version, exp: "^([0-9.-]+)", base: "cpe:/a:dell:powerprotect_data_domain:");
os_cpe = build_cpe(value: detected_version, exp: "^([0-9.-]+)", base: "cpe:/o:dell:data_domain_operating_system:");
if (!cpe) {
  cpe = "cpe:/a:dell:powerprotect_data_domain";
  os_cpe = "cpe:/o:dell:data_domain_operating_system";
}

os_register_and_report(os: "Dell PowerProtect Data Domain Operating System (DDOS)", cpe: os_cpe,
                       desc: "Dell PowerProtect Data Domain Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("dell/powerprotect/data_domain/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("dell/powerprotect/data_domain/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("dell/powerprotect/data_domain/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("dell/powerprotect/data_domain/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("dell/powerprotect/data_domain/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from SNMP sysDescr OID: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("dell/powerprotect/data_domain/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("dell/powerprotect/data_domain/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: app_name, version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n\n';
  report += chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

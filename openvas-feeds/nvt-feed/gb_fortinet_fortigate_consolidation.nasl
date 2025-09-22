# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147797");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2022-03-14 07:34:32 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fortinet FortiGate Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Fortinet FortiGate detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_fortinet_fortigate_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_fortinet_fortigate_snmp_detect.nasl",
                        "gsf/gb_fortinet_fortigate_http_detect.nasl");
  script_mandatory_keys("fortinet/fortigate/detected");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/next-generation-firewall");

  exit(0);
}

if (!get_kb_item("fortinet/fortigate/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
detected_patch = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp")) {
  model_list = get_kb_list("fortinet/fortigate/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("fortinet/fortigate/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("fortinet/fortigate/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "fortinet/fortigate/build", value: detected_build);
      break;
    }
  }
}

os_name = "Fortinet FortiOS";
hw_name = "Fortinet ";

if (detected_model != "unknown") {
  hw_name += detected_model;
  hw_cpe = "cpe:/h:fortinet:" + tolower(detected_model);
} else {
  hw_name += "FortiGate";
  hw_cpe = "cpe:/h:fortinet:fortigate";
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:fortinet:fortios:");
if (!os_cpe)
  os_cpe = "cpe:/o:fortinet:fortios";

if (http_ports = get_kb_list("fortinet/fortigate/http/port")) {

  set_kb_item(name: "fortinet/fortios_product/http/detected", value: TRUE);

  foreach port (http_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/http/detected", value: TRUE);

    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concludedUrl = get_kb_item("fortinet/fortigate/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("fortinet/fortigate/snmp/port")) {

  set_kb_item(name: "fortinet/fortios_product/snmp/detected", value: TRUE);

  foreach port (snmp_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/snmp/detected", value: TRUE);

    extra += 'SNMP on port ' + port + '/udp\n';

    concludedOID = get_kb_item("fortinet/fortigate/snmp/" + port + "/concludedOID");
    if (concludedOID) {
      concluded = get_kb_item("fortinet/fortigate/snmp/" + port + "/concluded");
      if (concluded)
        extra += '  Concluded from "' + concluded + '" via OID: ' + concludedOID + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_ports = get_kb_list("fortinet/fortigate/ssh-login/port")) {

  set_kb_item(name: "fortinet/fortios_product/ssh-login/detected", value: TRUE);

  foreach port (ssh_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/ssh-login/detected", value: TRUE);

    extra += 'SSH login on port ' + port + '/tcp\n';

    concluded = get_kb_item("fortinet/fortigate/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Fortinet FortiGate Detection Consolidation");
set_kb_item(name: "fortinet/fortios_product/detected", value: TRUE);

report  = build_detection_report(app: os_name, version: detected_version, build: detected_build,
                                 install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);

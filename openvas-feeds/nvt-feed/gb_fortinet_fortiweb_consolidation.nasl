# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170963");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-18 08:13:12 +0000 (Mon, 18 Nov 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fortinet FortiWeb Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Fortinet FortiWeb detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_fortinet_fortiweb_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_fortinet_fortiweb_http_detect.nasl",
                        "gsf/gb_fortinet_fortiweb_snmp_detect.nasl");
  script_mandatory_keys("fortinet/fortiweb/detected");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/web-application-firewall/fortiweb");

  exit(0);
}

if (!get_kb_item("fortinet/fortiweb/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
detected_patch = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("fortinet/fortiweb/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      build_patch_model_vers_extra += '\n- Version: ' + detected_version;
      break;
    }
  }

  build_list = get_kb_list("fortinet/fortiweb/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      build_patch_model_vers_extra += '\n- Build:   ' + detected_build;
      set_kb_item(name: "fortinet/fortiweb/build", value: detected_build);
      break;
    }
  }

  model_list = get_kb_list("fortinet/fortiweb/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      build_patch_model_vers_extra += '\n- Model:   ' + detected_model;
      # VMs and containers are:
      # VM02, VM04, VM08, VM16, VMC01, VMC02, VMC04, VMC08
      # according to the model overview while hardware appliances are:
      # 100F, 400F, 600F, 1000F, 2000F, 3000F, 4000F
      if (detected_model =~ "^[0-9]+")
        hw_cpe = "cpe:/h:fortinet:" + tolower(detected_model);
      break;
    }
  }
}

if (build_patch_model_vers_extra)
  build_patch_model_vers_extra = '\n\nExtracted device info:' + build_patch_model_vers_extra;

os_cpe = "cpe:/o:fortinet:fortios";
os_register_and_report(os: "Fortinet FortiOS", cpe: os_cpe, runs_key: "unixoide",
                       desc: "Fortinet FortiWeb Detection Consolidation");
set_kb_item(name: "fortinet/fortios_product/detected", value: TRUE);

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:fortinet:fortiweb:");
if (!cpe)
  cpe = "cpe:/a:fortinet:fortiweb";

if (http_ports = get_kb_list("fortinet/fortiweb/http/port")) {

  set_kb_item(name: "fortinet/fortios_product/http/detected", value: TRUE);

  extra += '- Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/http/detected", value: TRUE);

    extra += "  - Port: " + port + "/tcp";

    concluded = get_kb_item("fortinet/fortiweb/http/" + port + "/concluded");
    if (concluded)
      extra += '\n  - Concluded from version/product identification result:\n' + concluded;

    concludedUrl = get_kb_item("fortinet/fortiweb/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '\n  - Concluded from version/product identification location:\n' + concludedUrl;

    _extra = get_kb_item("fortinet/fortiweb/http/" + port + "/extra");
    if (_extra)
      extra += '\n' + _extra;

    register_product(cpe: cpe, location: location, port: port, service: "www");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("fortinet/fortiweb/snmp/port")) {

  set_kb_item(name: "fortinet/fortios_product/snmp/detected", value: TRUE);

  foreach port (snmp_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/snmp/detected", value: TRUE);

    extra += '- SNMP on port ' + port + '/udp\n';

    concludedOID = get_kb_item("fortinet/fortiweb/snmp/" + port + "/concludedOID");
    if (concludedOID) {
      concluded = get_kb_item("fortinet/fortiweb/snmp/" + port + "/concluded");
      if (concluded)
        extra += '  - Concluded from "' + concluded + '" via OID: ' + concludedOID + '\n';
    }

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_ports = get_kb_list("fortinet/fortiweb/ssh-login/port")) {

  set_kb_item(name: "fortinet/fortios_product/ssh-login/detected", value: TRUE);

  foreach port (ssh_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/ssh-login/detected", value: TRUE);

    extra += "- SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("fortinet/fortiweb/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  - Concluded from version/product identification result:\n  ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}


report  = build_detection_report(app: "Fortinet FortiWeb", version: detected_version, build: detected_build,
                                 install: location, cpe: cpe);
if (hw_cpe) {
  report += '\n\n';
  report += build_detection_report(app: "Fortinet FortiWeb " + detected_model, skip_version: TRUE, cpe: hw_cpe, install: location);
}

report += build_patch_model_vers_extra;

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);

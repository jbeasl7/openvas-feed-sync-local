# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114880");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-16 09:28:41 +0000 (Mon, 16 Dec 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fortinet FortiManager Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Fortinet FortiManager detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_fortinet_fortimanager_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_fortinet_fortimanager_http_detect.nasl");
  script_mandatory_keys("fortinet/fortimanager/detected");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/management/fortimanager");

  exit(0);
}

if (!get_kb_item("fortinet/fortimanager/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

# nb: Version and build currently only extracted via SSH login
foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("fortinet/fortimanager/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      build_model_vers_extra += '\n- Version: ' + detected_version;
      break;
    }
  }

  build_list = get_kb_list("fortinet/fortimanager/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      build_model_vers_extra += '\n- Build:   ' + detected_build;
      set_kb_item(name: "fortinet/fortimanager/build", value: detected_build);
      break;
    }
  }

  model_list = get_kb_list("fortinet/fortimanager/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      build_model_vers_extra += '\n- Model:   ' + detected_model;
      # VMs and containers are:
      # FMG-VM64, FMG-VM64-KVM
      # according to the model overview while hardware appliances are:
      # 200G, 400G, 600F, 1000F, 3000G, 3700G
      if (detected_model =~ "^[0-9]+")
        hw_cpe = "cpe:/h:fortinet:" + tolower(detected_model);
      set_kb_item(name: "fortinet/fortimanager/model", value: detected_model);
      break;
    }
  }
}

if (build_model_vers_extra)
  build_model_vers_extra = '\n\nExtracted device info:' + build_model_vers_extra;

os_cpe = "cpe:/o:fortinet:fortios";
os_register_and_report(os: "Fortinet FortiOS", cpe: os_cpe, runs_key: "unixoide",
                       desc: "Fortinet FortiManager Detection Consolidation");
set_kb_item(name: "fortinet/fortios_product/detected", value: TRUE);

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:fortinet:fortimanager:");
if (!cpe)
  cpe = "cpe:/a:fortinet:fortimanager";

if (ssh_ports = get_kb_list("fortinet/fortimanager/ssh-login/port")) {

  set_kb_item(name: "fortinet/fortios_product/ssh-login/detected", value: TRUE);

  foreach port (ssh_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/ssh-login/detected", value: TRUE);

    extra += "- SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("fortinet/fortimanager/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  - Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (http_ports = get_kb_list("fortinet/fortimanager/http/port")) {

  set_kb_item(name: "fortinet/fortios_product/http/detected", value: TRUE);

  extra += '- Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/http/detected", value: TRUE);

    extra += "  - Port: " + port + "/tcp";

    concluded = get_kb_item("fortinet/fortimanager/http/" + port + "/concluded");
    if (concluded)
      extra += '\n  - Concluded from version/product identification result:\n' + concluded;

    concludedUrl = get_kb_item("fortinet/fortimanager/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '\n  - Concluded from version/product identification location:\n' + concludedUrl;

    _extra = get_kb_item("fortinet/fortimanager/http/" + port + "/extra");
    if (_extra)
      extra += '\n' + _extra;

    register_product(cpe: cpe, location: location, port: port, service: "www");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

report  = build_detection_report(app: "Fortinet FortiManager", version: detected_version, build: detected_build,
                                 install: location, cpe: cpe);
if (hw_cpe) {
  report += '\n\n';
  report += build_detection_report(app: "Fortinet FortiManager " + detected_model, skip_version: TRUE, cpe: hw_cpe, install: location);
}

report += build_model_vers_extra;

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154849");
  script_version("2025-07-10T05:42:18+0000");
  script_tag(name:"last_modification", value:"2025-07-10 05:42:18 +0000 (Thu, 10 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-06-27 05:11:55 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Identity Services Engine (ISE) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_ise_http_detect.nasl",
                      "gb_cisco_ise_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_ise_snmp_detect.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco Identity Services Engine (ISE)
  detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html");

  exit(0);
}

if (!get_kb_item("cisco/ise/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_patch = "unknown";
location = "/";

# nb: Currently version only obtained via SSH login and SNMP
foreach source (make_list("ssh-login", "snmp")) {
  version_list = get_kb_list("cisco/ise/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  patch_list = get_kb_list("cisco/ise/" + source + "/*/patch");
  foreach patch (patch_list) {
    if (patch != "unknown" && detected_patch == "unknown") {
      detected_patch = patch;
      set_kb_item(name: "cisco/ise/patch", value: detected_patch);
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:identity_services_engine:");
if (!cpe)
  cpe = "cpe:/a:cisco:identity_services_engine";

# nb: Currently only used for the SNMP detection as:
# - HTTP doesn't expose this info
# - SSH login-based detection via gather-package-list.nasl is already extracting, registering and
#   reporting a more detailed version (The SNMP service is only providing the major version)
if (os_version = get_kb_item("cisco/ise/os_version"))
  os_cpe = "cpe:/o:cisco:application_deployment_engine:" + os_version;
else
  os_cpe = "cpe:/o:cisco:application_deployment_engine";

os_register_and_report(os: "Cisco Application Deployment Engine OS (ADE-OS)",
                       cpe: os_cpe,
                       desc: "Cisco Identity Services Engine (ISE) Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("cisco/ise/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("cisco/ise/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("cisco/ise/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/ise/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("cisco/ise/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/ise/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Cisco Identity Services Engine (ISE)", version: detected_version,
                                patch: detected_patch, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

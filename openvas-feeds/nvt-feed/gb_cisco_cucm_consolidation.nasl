# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147755");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-03-04 08:26:58 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Unified Communications Manager (CUCM) Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Cisco Unified Communications Manager
  (CUCM, formerly Call Manager) detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_cucm_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_cucm_http_detect.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/unified-communications/unified-communications-manager-callmanager/index.html");

  exit(0);
}

if (!get_kb_item("cisco/cucm/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("cisco/cucm/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

app_name = "Cisco Unified Communications Manager (CUCM)";

cpe = build_cpe(value: detected_version, exp: "^([0-9.-]+)",
                base: "cpe:/a:cisco:unified_communications_manager:");
if (!cpe)
  cpe = "cpe:/a:cisco:unified_communications_manager";

if (http_ports = get_kb_list("cisco/cucm/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/cucm/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concUrl = get_kb_item("cisco/cucm/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_ports = get_kb_list("cisco/cucm/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH login on port ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/cucm/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

os_register_and_report(os: "Cisco Unified Communications Operating System (UCOS)", cpe: "cpe:/o:cisco:ucos", runs_key: "unixoide",
                       desc: "Cisco Unified Communications Manager (CUCM) Detection Consolidation");

report  = build_detection_report(app: app_name, version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);

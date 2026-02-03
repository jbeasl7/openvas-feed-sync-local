# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96206");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"creation_date", value:"2011-06-06 16:48:59 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco IOS Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_ios_snmp_detect.nasl",
                        "gsf/gb_cisco_ios_ssh_login_detect.nasl");
  script_mandatory_keys("cisco/ios/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco IOS detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-software-releases-listing.html");

  exit(0);
}

if (!get_kb_item("cisco/ios/detected"))
  exit(0);

include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp")) {
  model_list = get_kb_list("cisco/ios/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/ios/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("cisco/ios/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_name = "Cisco IOS Software";

if (detected_version != "unknown")
  os_cpe = "cpe:/o:cisco:ios:" + detected_version;
else
  os_cpe = "cpe:/o:cisco:ios";

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Cisco IOS Detection Consolidation",
                       runs_key: "unixoide");

if (detected_model != "unknown") {
  hw_name = "Cisco IOS " + detected_model;
  cpe_model = str_replace(string: tolower(detected_model), find: "/", replace: "-");
  hw_cpe = "cpe:/h:cisco:" + cpe_model;
}

if (snmp_ports = get_kb_list("cisco/ios/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("cisco/ios/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  SNMP banner: " + concluded + '\n';

    concludedMod = get_kb_item("cisco/ios/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("cisco/ios/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Model concluded from: "' + concludedMod + '" via OID: "' + concludedModOID + '"\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("cisco/ios/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/ios/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from "show version" command:\n' + chomp(concluded) + '\n';

    register_product(cpe: os_cpe, location: location, port: 0, service: "ssh-login");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: 0, service: "ssh-login");
  }
}

report = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
if (hw_cpe) {
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);
}

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

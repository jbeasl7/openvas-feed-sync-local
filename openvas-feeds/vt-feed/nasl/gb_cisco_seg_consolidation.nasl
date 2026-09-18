# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105440");
  script_version("2026-09-17T05:45:41+0000");
  script_tag(name:"last_modification", value:"2026-09-17 05:45:41 +0000 (Thu, 17 Sep 2026)");
  script_tag(name:"creation_date", value:"2015-11-09 13:54:40 +0100 (Mon, 09 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Secure Email Gateway (SEG) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_seg_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_seg_snmp_detect.nasl",
                        "gsf/gb_cisco_seg_ssh_login_detect.nasl");
  script_mandatory_keys("cisco/seg/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco Secure Email Gateway (SEG) (formerly
  Cisco Email Security Appliance (ESA)) detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/security/email-security-appliance/series.html");

  exit(0);
}

if (!get_kb_item("cisco/seg/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http", "snmp")) {
  model_list = get_kb_list("cisco/seg/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/seg/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("cisco/seg/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

app_cpe = build_cpe(value: detected_version, exp: "^([0-9.-]+)", base: "cpe:/a:cisco:secure_email_gateway:");
os_cpe = build_cpe(value: detected_version, exp: "^([0-9.-]+)", base: "cpe:/o:cisco:asyncos:");
if (!app_cpe) {
  app_cpe = "cpe:/a:cisco:secure_email_gateway";
  os_cpe = "cpe:/o:cisco:asyncos";
}

os_register_and_report(os: "Cisco AsyncOS", version: detected_version, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Cisco Secure Email Gateway (SEG) Detection Consolidation");

if (detected_model != "unknown") {
  hw_name = "Cisco Secure Email Gateway (SEG) " + detected_model;

  if (detected_model !~ "^C[0-9]+V")
    hw_cpe = "cpe:/h:cisco:secure_email_gateway_" + tolower(detected_model);
}

if (http_ports = get_kb_list("cisco/seg/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/seg/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("cisco/seg/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("cisco/seg/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("cisco/seg/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  SNMP banner: " + concluded + '\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("cisco/seg/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/seg/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: "Cisco Secure Email Gateway (SEG)", version: detected_version,
                                 install: location, cpe: app_cpe);
if (hw_name) {
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);
}

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144208");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"creation_date", value:"2020-07-02 07:28:21 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fortinet FortiMail Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Fortinet FortiMail detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_fortinet_fortimail_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_fortinet_fortimail_http_detect.nasl");
  script_mandatory_keys("fortinet/fortimail/detected");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/email-security");

  exit(0);
}

if (!get_kb_item("fortinet/fortimail/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("fortinet/fortimail/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_cpe = "cpe:/o:fortinet:fortios";
os_register_and_report(os: "Fortinet FortiOS", cpe: os_cpe, desc: "Fortinet FortiMail Detection Consolidation", runs_key: "unixoide");
set_kb_item(name: "fortinet/fortios_product/detected", value: TRUE);

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:fortinet:fortimail:");
if (!cpe)
  cpe = "cpe:/a:fortinet:fortimail";

if (ssh_login_ports = get_kb_list("fortinet/fortimail/ssh-login/port")) {

  set_kb_item(name: "fortinet/fortios_product/ssh-login/detected", value: TRUE);

  extra += '  Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/ssh-login/detected", value: TRUE);

    extra += '    Port: ' + port + '/tcp\n';

    concluded = get_kb_item("fortinet/fortimail/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '    Concluded from version/product identification result:\n' + concluded;

    register_product(cpe: cpe, location: location, port: 0, service: "ssh-login");
    register_product(cpe: os_cpe, location: location, port: 0, service: "ssh-login");
  }
}

if (http_ports = get_kb_list("fortinet/fortimail/http/port")) {

  set_kb_item(name: "fortinet/fortios_product/http/detected", value: TRUE);

  if (extra)
    extra += '\n\n';

  extra += '  Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {

    set_kb_item(name: "fortinet/fortios_product/" + port + "/http/detected", value: TRUE);

    extra += '    Port: ' + port + '/tcp\n';

    concluded = get_kb_item("fortinet/fortimail/http/" + port + "/concludedUrl");
    if (concluded)
      extra += '    Concluded from version/product identification location:\n' + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: "Fortinet FortiMail", version: detected_version, cpe: cpe, install: location);

if (extra) {
  report += '\n\nDetection methods:\n\n';
  report += extra;
}

log_message(port: 0, data: chomp(report));

exit(0);

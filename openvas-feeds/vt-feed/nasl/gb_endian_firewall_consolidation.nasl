# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156935");
  script_version("2026-05-08T06:16:21+0000");
  script_tag(name:"last_modification", value:"2026-05-08 06:16:21 +0000 (Fri, 08 May 2026)");
  script_tag(name:"creation_date", value:"2026-05-07 02:33:25 +0000 (Thu, 07 May 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Endian Firewall Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_endian_firewall_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_endian_firewall_http_detect.nasl");
  script_mandatory_keys("endian/firewall/detected");

  script_tag(name:"summary", value:"Consolidation of Endian Firewall detections.");

  script_xref(name:"URL", value:"https://www.endian.com/en/community/");

  exit(0);
}

if (!get_kb_item("endian/firewall/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("endian/firewall/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Endian Firewall Detection Consolidation");

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:endian:firewall_community:");
if (!cpe)
  cpe = "cpe:/a:endian:firewall_community";

if (http_ports = get_kb_list("endian/firewall/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("endian/firewall/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("endian/firewall/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("endian/firewall/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login on port " + port + '/tcp\n';

    concluded = get_kb_item("endian/firewall/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: 0, service: "ssh-login");
  }
}

report = build_detection_report(app: "Endian Firewall", version: detected_version, install: location,
                                cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154908");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-10 09:25:08 +0000 (Thu, 10 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Puppet Enterprise Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_puppet_enterprise_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_puppet_enterprise_ssh_login_detect.nasl");
  script_mandatory_keys("puppet/enterprise/detected");

  script_tag(name:"summary", value:"Consolidation of Puppet Enterprise detections.");

  script_xref(name:"URL", value:"https://www.puppet.com/products/puppet-enterprise");

  exit(0);
}

if (!get_kb_item("puppet/enterprise/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("puppet/enterprise/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:puppet:enterprise:");
if (!cpe)
  cpe = "cpe:/a:puppet:enterprise";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                      desc: "Puppet Enterprise Detection Consolidation");

if (http_ports = get_kb_list("puppet/enterprise/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("puppet/enterprise/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("puppet/enterprise/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    error = get_kb_item("puppet/enterprise/http/" + port + "/error");
    if (error)
      extra += error + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("puppet/enterprise/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login on port " + port + '/tcp\n';

    concluded = get_kb_item("puppet/enterprise/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: "Puppet Enterprise", version: detected_version, install: location,
                                 cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142665");
  script_version("2024-12-06T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-12-06 05:05:38 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"creation_date", value:"2019-07-24 08:15:46 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Jenkins Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Jenkins automation server detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sw_jenkins_http_detect.nasl", "gb_jenkins_udp_detect.nasl",
                      "gb_jenkins_cli_tcp_detect.nasl");
  script_mandatory_keys("jenkins/detected");

  script_xref(name:"URL", value:"https://www.jenkins.io/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("jenkins/detected"))
  exit(0);

report = "";
default_install = "/";

if (http_ports = get_kb_list("jenkins/http/port")) {
  http_ports = sort(http_ports);

  foreach port (http_ports) {
    version = get_kb_item("jenkins/http/" + port + "/version");
    if (!version)
      version = "unknown";
    else
      concl = get_kb_item("jenkins/http/" + port + "/concluded");

    location = get_kb_item("jenkins/http/" + port + "/location");

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jenkins:jenkins:");
    if (!cpe)
      cpe = "cpe:/a:jenkins:jenkins";

    register_product(cpe: cpe, location: location, port: port, service: "www");

    if (report)
      report += '\n\n';

    extra = "- Detected on HTTP(s) port " + port + "/tcp";

    whoami = get_kb_item("jenkins/" + port + "/" + location + "/whoami_url");
    if (whoami) {
      extra += '\n- The "Who am I" page which might provide additional information about ';
      extra += "the Jenkins installation is available at: " + whoami;
    }

    report += build_detection_report(app: "Jenkins", version: version, install: location, cpe: cpe,
                                     concluded: concl, extra: extra);
  }
}

if (disc_ports = get_kb_list("jenkins/autodiscovery/port")) {
  disc_ports = sort(disc_ports);

  foreach port (disc_ports) {

    version = get_kb_item("jenkins/autodiscovery/" + port + "/version");
    concl = get_kb_item("jenkins/autodiscovery/" + port + "/concluded");

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jenkins:jenkins:");
    if (!cpe)
      cpe = "cpe:/a:jenkins:jenkins";

    register_product(cpe: cpe, location: default_install, port: port, proto: "udp", service: "jenkins-autodiscovery");

    if (report)
      report += '\n\n';

    report += build_detection_report(app: "Jenkins", version: version,
                                     install: default_install, cpe: cpe, concluded: concl,
                                     extra: "- Detected on auto-discovery port " + port + "/udp");
  }
}

if (cli_ports = get_kb_list("jenkins/jenkins_cli/port")) {
  cli_ports = sort(cli_ports);

  foreach port (cli_ports) {

    concl = get_kb_item("jenkins/jenkins_cli/" + port + "/concluded");

    cpe = "cpe:/a:jenkins:jenkins";

    register_product(cpe: cpe, location: default_install, port: port, service: "jenkins_cli");

    if (report)
      report += '\n\n';

    report += build_detection_report(app: "Jenkins", version: version,
                                     install: default_install, cpe: cpe, concluded: concl,
                                     extra: "- Detected on Jenkins CLI subsystem port " + port + "/tcp");
  }
}

log_message(port: 0, data: report);

exit(0);

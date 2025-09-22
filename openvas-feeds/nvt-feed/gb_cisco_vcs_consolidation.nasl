# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151764");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-20 06:53:28 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco TelePresence Video Communication Server (VCS) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_vcs_ssh_login_detect.nasl",
                      "gb_cisco_vcs_sip_detect.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco TelePresence Video Communication Server
  (VCS) detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/unified-communications/telepresence-video-communication-server-vcs/series.html");

  exit(0);
}

if (!get_kb_item("cisco/vcs/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "sip")) {
  version_list = get_kb_list("cisco/vcs/" + source + "/*/version");
  foreach version (version_list) {
    detected_version = version;
    break;
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:telepresence_video_communication_server_software:");
if (!cpe)
  cpe = "cpe:/a:cisco:telepresence_video_communication_server_software";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Cisco TelePresence Video Communication Server (VCS) Detection Consolidation");

if (ssh_ports = get_kb_list("cisco/vcs/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += "SSH login via port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/vcs/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

if (sip_ports = get_kb_list("cisco/vcs/sip/port")) {
  foreach port (sip_ports) {
    proto = get_kb_item("cisco/vcs/sip/" + port + "/proto");

    extra += "SIP on port " + port + "/" + proto + '\n';

    concluded = get_kb_item("cisco/vcs/sip/" + port + "/concluded");
    if (concluded)
      extra += "  SIP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "sip", proto: proto);
  }
}

report = build_detection_report(app: "Cisco TelePresence Video Communication Server (VCS)",
                                version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);

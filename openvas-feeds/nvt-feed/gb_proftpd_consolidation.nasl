# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155379");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-22 05:37:04 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ProFTPD Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_proftpd_ftp_detect.nasl",
                      "gb_proftpd_ssh_login_detect.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"Consolidation of ProFTPD detections.");

  script_xref(name:"URL", value:"http://www.proftpd.org/");

  exit(0);
}

if (!get_kb_item("proftpd/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "ftp")) {
  version_list = get_kb_list("proftpd/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9.]+)([a-z0-9]+)?",
                base: "cpe:/a:proftpd:proftpd:");
if (!cpe)
  cpe = "cpe:/a:proftpd:proftpd";

if (ftp_ports = get_kb_list("proftpd/ftp/port")) {
  foreach port (ftp_ports) {
    extra += "FTP on port " + port + '/tcp\n';

    concluded = get_kb_item("proftpd/ftp/" + port + "/concluded");
    if (concluded)
      extra += "  FTP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ftp");
  }
}

if (ssh_login_ports = get_kb_list("proftpd/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("proftpd/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concludedCmd = get_kb_item("proftpd/ssh-login/" + port + "/concludedCmd");
    if (concludedCmd)
      extra += "  Concluded from version/product identification command: " + concludedCmd + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: "ProFTPD", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);

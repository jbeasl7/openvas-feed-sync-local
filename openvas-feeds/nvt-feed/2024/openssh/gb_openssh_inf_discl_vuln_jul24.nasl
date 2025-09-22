# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114681");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-01 13:29:27 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-39894");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH 9.5p1 - 9.7p1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vendor insights:

  2) Logic error in ssh(1) ObscureKeystrokeTiming

  In OpenSSH, when connected to an OpenSSH server version 9.5 or later, a logic error in the ssh(1)
  ObscureKeystrokeTiming feature (on by default) rendered this feature ineffective - a passive
  observer could still detect which network packets contained real keystrokes when the
  countermeasure was active because both fake and real keystroke packets were being sent
  unconditionally.

  This bug was found by Philippos Giavridis and also independently by Jacky Wei En Kung, Daniel
  Hugenroth and Alastair Beresford of the University of Cambridge Computer Lab.

  Worse, the unconditional sending of both fake and real keystroke packets broke another
  long-standing timing attack mitigation. Since OpenSSH 2.9.9 sshd(8) has sent fake keystroke echo
  packets for traffic received on TTYs in echo-off mode, such as when entering a password into su(8)
  or sudo(8). This bug rendered these fake keystroke echoes ineffective and could allow a passive
  observer of a SSH session to once again detect when echo was off and obtain fairly limited timing
  information about keystrokes in this situation (20ms granularity by default).

  This additional implication of the bug was identified by Jacky Wei En Kung, Daniel Hugenroth and
  Alastair Beresford and we thank them for their detailed analysis.

  This bug does not affect connections when ObscureKeystrokeTiming was disabled or sessions where no
  TTY was requested.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH versions 9.5p1 through 9.7p1.");

  script_tag(name:"solution", value:"Update to version 9.8 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-9.8");
  script_xref(name:"URL", value:"https://www.openssh.com/security.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.5p1", test_version2: "9.7p1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

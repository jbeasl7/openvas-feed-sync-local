# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105000");
  script_version("2025-05-23T05:40:17+0000");
  script_tag(name:"last_modification", value:"2025-05-23 05:40:17 +0000 (Fri, 23 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-09 13:32:27 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-22 16:51:54 +0000 (Thu, 22 May 2025)");

  script_cve_id("CVE-2025-32728");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH 7.4 - 9.9 Unspecified Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to an unspecified vulnerability due to
  a logic error.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A logic error in sshd(8) caused the DisableForwarding option to
  not disable X11 or agent forwarding as documented. Note that X11 forwarding is disabled by default
  in sshd(8) and agent forwarding is not requested by default by ssh(1).");

  script_tag(name:"affected", value:"OpenBSD OpenSSH versions 7.4 through 9.9.");

  script_tag(name:"solution", value:"Update to version 10.0 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-10.0");
  script_xref(name:"URL", value:"https://www.openssh.com/security.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/04/09/1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358767");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.4", test_version_up: "10.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

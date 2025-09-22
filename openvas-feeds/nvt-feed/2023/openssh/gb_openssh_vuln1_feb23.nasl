# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104510");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-02-03 13:51:53 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-07 20:18:00 +0000 (Tue, 07 Mar 2023)");

  script_cve_id("CVE-2023-25136");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH 9.1 Memory Safety Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to a memory safety vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Fix a pre-authentication double-free memory fault introduced in
  OpenSSH 9.1. This is not believed to be exploitable, and it occurs in the unprivileged pre-auth
  process that is subject to chroot and is further sandboxed on most major platforms.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH version 9.1 only.");

  script_tag(name:"solution", value:"Update to version 9.2 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/releasenotes.html#9.2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/02/02/3");
  script_xref(name:"URL", value:"https://bugzilla.mindrot.org/show_bug.cgi?id=3522");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/02/02/2");

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

if (version_is_equal(version: version, test_version: "9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

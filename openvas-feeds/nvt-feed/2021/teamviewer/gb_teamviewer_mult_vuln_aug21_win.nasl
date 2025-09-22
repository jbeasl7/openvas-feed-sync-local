# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teamviewer:teamviewer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146978");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-10-26 09:54:48 +0000 (Tue, 26 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-27 17:48:00 +0000 (Wed, 27 Oct 2021)");

  script_cve_id("CVE-2021-34858", "CVE-2021-34859", "CVE-2021-35005");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamViewer Multiple Vulnerabilities (Aug 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/detected");

  script_tag(name:"summary", value:"TeamViewer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-34858: Installations with existing TV recording files (TVS) are vulnerable to a problem
  in file parsing that could allow someone to execute arbitrary code and could cause the binary to
  crash. User interaction as well as a third-party vulnerability are required for remote
  exploitation.

  - CVE-2021-34859: In some circumstances, a problem in shared memory management could cause the
  TeamViewer service to perform an out-of-bounds read. Access to the machine is required for
  exploitation.

  - CVE-2021-35005: TeamViewer is installed by default in the protected Program Files directory. If
  a user intentionally had chosen to install it in a different location, someone would have been
  able to leverage a privilege escalation problem. Access to the machine would have been required
  for exploitation.");

  script_tag(name:"affected", value:"TeamViewer versions 15.x prior to 15.21.4.");

  script_tag(name:"solution", value:"Update to version 15.21.4 or later.");

  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/117794/august-updates-security-patches/p1");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-21-1003/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-082/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "15.0", test_version2: "15.21.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.21.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

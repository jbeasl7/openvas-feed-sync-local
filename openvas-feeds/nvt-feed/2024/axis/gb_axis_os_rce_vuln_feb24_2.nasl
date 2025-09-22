# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:axis:axis_os";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.127709");
  script_version("2024-03-06T05:05:53+0000");
  script_tag(name:"last_modification", value:"2024-03-06 05:05:53 +0000 (Wed, 06 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-02-28 07:26:59 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 00:37:47 +0000 (Tue, 13 Feb 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-5800");

  script_name("AXIS OS RCE Vulnerability (Feb 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS OS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An insufficient input validation in the VAPIX API
  create_overlay.cgi which leads to a remote code execution.");

  script_tag(name:"affected", value:"AXIS OS version prior to 6.50.5.16, 7.x prior to 8.40.40,
  9.x prior to 9.80.55, 10.x prior to 10.12.220 and 11.x prior to 11.8.61.");

  script_tag(name:"solution", value:"Update to version 6.50.5.16, 8.40.40, 9.80.47, 10.12.206,
  11.8.61 or later.");

  script_xref(name:"URL", value:"https://www.axis.com/dam/public/89/d9/99/cve-2023-5800-en-US-424339.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.50.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.50.5.16");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "8.40.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.40.40");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.80.55")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.80.55");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.12.220")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.12.220");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.8.61")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.61");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);

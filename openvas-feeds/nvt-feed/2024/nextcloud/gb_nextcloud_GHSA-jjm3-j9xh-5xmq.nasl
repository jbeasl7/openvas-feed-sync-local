# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127779");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-06-19 11:00:29 +0000 (Wed, 19 Jun 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-19 14:57:28 +0000 (Fri, 19 Jul 2024)");

  script_cve_id("CVE-2024-37882");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 23.0.12.17, 24.x < 24.0.12.13, 25.x < 25.0.13.8, 26.x < 26.0.13, 27.x < 27.1.8, 28.x < 28.0.4 Improper Access control Vulnerability (GHSA-jjm3-j9xh-5xmq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A recipient of a share with read&share permissions could
  reshare the item with more permissions.");

  script_tag(name:"affected", value:"Nextcloud Server versions prior to 23.0.12.17, 24.x prior to
  24.0.12.13, 25.x prior to 25.0.13.8, 26.x prior to 26.0.13, 27.x prior to 27.1.8 and 28.x
  prior to 28.0.4.");

  script_tag(name:"solution", value:"Update to version 23.0.12.17, 24.0.12.13, 25.0.13.8, 26.0.13,
  27.1.8, 28.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-jjm3-j9xh-5xmq");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "23.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.12.17 (Nextcloud Enterprise only)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.0.0", test_version_up: "24.0.12.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.12.13 (Nextcloud Enterprise only)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "25.0.0", test_version_up: "25.0.13.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "25.0.13.8 (Nextcloud Enterprise only)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "26.0.0", test_version_up: "26.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "27.0.0", test_version_up: "27.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "27.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "28.0.0", test_version_up: "28.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

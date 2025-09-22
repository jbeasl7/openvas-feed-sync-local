# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128031");
  script_version("2025-03-07T15:40:19+0000");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-07-29 10:00:00 +0000 (Mon, 29 Jul 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2024-32111");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Jun 2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-32111: Improper limitation of a pathname to a restricted directory vulnerability in
  'Automatic WordPress' allows Relative Path Traversal.");

  script_tag(name:"affected", value:"WordPress version 6.5.4 and prior.");

  script_tag(name:"solution", value:"Update to version 4.1.41, 4.2.38, 4.3.34, 4.4.33, 4.5.32,
  4.6.29, 4.7.29, 4.8.25, 4.9.26, 5.0.22, 5.1.19, 5.2.21, 5.3.18, 5.4.16, 5.5.15, 5.6.14, 5.7.12,
  5.8.10, 5.9.10, 6.0.9, 6.1.7, 6.2.6, 6.3.5, 6.4.5, 6.5.5 or later");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-655-authenticated-contributor-directory-traversal?asset_slug=wordpress");
  script_xref(name:"URL", value:"https://wordpress.org/news/2024/06/wordpress-6-5-5/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.9", test_version_up: "5.9.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "6.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.3", test_version_up: "6.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.5", test_version_up: "6.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

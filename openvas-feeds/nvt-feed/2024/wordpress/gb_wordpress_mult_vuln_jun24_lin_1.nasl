# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128032");
  script_version("2025-03-07T15:40:19+0000");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-07-30 10:00:00 +0000 (Tue, 30 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-25 11:15:50 +0000 (Tue, 25 Jun 2024)");

  script_cve_id("CVE-2024-31111", "CVE-2024-6307");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Jun 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-31111: Improper neutralization of input during web page generation in
    'Automatic WordPress' allows Stored Cross-site Scripting vulnerability (XSS).

  - CVE-2024-6307: Insufficient input sanitization and output escaping on URLs in HTML API allows
    Stored Cross-site Scripting (XSS).");

  script_tag(name:"affected", value:"WordPress version 6.5.4 and prior.");

  script_tag(name:"solution", value:"Update to version 5.9.10, 6.0.9, 6.1.7, 6.2.6, 6.3.5, 6.4.5,
  6.5.5 or later");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/bc0d36f8-6569-49a1-b722-5cf57c4bb32a?source=cve");
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

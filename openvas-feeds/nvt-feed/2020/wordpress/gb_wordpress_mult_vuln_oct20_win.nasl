# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144873");
  script_version("2025-05-13T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2020-11-02 05:00:25 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-11 03:15:00 +0000 (Wed, 11 Nov 2020)");

  script_cve_id("CVE-2020-28032", "CVE-2020-28033", "CVE-2020-28034", "CVE-2020-28035",
                "CVE-2020-28036", "CVE-2020-28037", "CVE-2020-28038", "CVE-2020-28039",
                "CVE-2020-28040", "CVE-2021-29476");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Oct 2020) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-28032, CVE-2021-29476: Insecure Deserialization in the used PHP Requests library

  - CVE-2020-28033: Mishanding of embeds from disabled sites on a multisite network

  - CVE-2020-28034, CVE-2020-28038: Multiple cross-site scripting (XSS)

  - CVE-2020-28035, CVE-2020-28036: Privilege escalation in XML-RPC

  - CVE-2020-28037: DoS attack which could lead to a remote code execution (RCE)

  - CVE-2020-28039: Arbitrary file deletion

  - CVE-2020-28040: Cross-site request forgery (CSRF)");

  script_tag(name:"affected", value:"WordPress versions 3.7 through 5.5.1. Older versions might be
  affected as well.");

  script_tag(name:"solution", value:"Update to version 3.7.35, 3.8.35, 3.9.33, 4.0.32, 4.1.32,
  4.2.29, 4.3.25, 4.4.24, 4.5.23, 4.6.20, 4.7.19, 4.8.15, 4.9.16, 5.0.11, 5.1.7, 5.2.8, 5.3.5,
  5.4.3, 5.5.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/");
  script_xref(name:"URL", value:"https://github.com/WordPress/Requests/security/advisories/GHSA-52qp-jpq7-6c54");

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

if (version_is_less(version: version, test_version: "3.7.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2", test_version2: "4.2.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4", test_version2: "4.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5", test_version2: "4.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.6", test_version2: "4.6.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7", test_version2: "4.7.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8", test_version2: "4.8.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9", test_version2: "4.9.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4", test_version2: "5.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

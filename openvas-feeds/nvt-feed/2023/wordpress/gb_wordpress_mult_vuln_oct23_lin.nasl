# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104986");
  script_version("2023-11-09T05:05:33+0000");
  script_tag(name:"last_modification", value:"2023-11-09 05:05:33 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-13 09:35:24 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 17:04:00 +0000 (Mon, 16 Oct 2023)");

  script_cve_id("CVE-2023-38000", "CVE-2023-39999", "CVE-2023-5561");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Oct 2023) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-5561: Potential disclosure of user email addresses

  - No CVE: Remote code execution (RCE) POP Chains vulnerability

  - CVE-2023-38000: Cross-site scripting (XSS) issue in the post link navigation block

  - CVE-2023-39999: Comments on private posts could be leaked to other users

  - No CVE: A way for logged-in users to execute any shortcode

  - No CVE: XSS vulnerability in the application password screen

  - No CVE: XSS vulnerability in the footnotes block

  - No CVE: Cache poisoning denial of service (DoS) vulnerability");

  script_tag(name:"affected", value:"WordPress version 6.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.1.39, 4.2.36, 4.3.32, 4.4.31, 4.5.30,
  4.6.27, 4.7.27, 4.8.23, 4.9.24, 5.0.20, 5.1.17, 5.2.19, 5.3.16, 5.4.14, 5.5.13, 5.6.12, 5.7.10,
  5.8.8, 5.9.8, 6.0.6, 6.1.4, 6.2.3, 6.3.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2023/10/wordpress-6-3-2-security-release-what-you-need-to-know/");
  script_xref(name:"URL", value:"https://patchstack.com/articles/wordpress-core-6-3-2-security-update-technical-advisory");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wordpress/wordpress-core-6-3-2-contributor-stored-xss-in-navigation-links-block-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wordpress/wordpress-wordpress-core-core-6-3-2-contributor-comment-read-on-private-and-password-protected-post-vulnerability");
  script_xref(name:"URL", value:"https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441");

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

if (version_is_less(version: version, test_version: "4.1.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5", test_version_up: "4.5.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.6", test_version_up: "4.6.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.7", test_version_up: "4.7.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.7", test_version_up: "5.7.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.8", test_version_up: "5.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.9", test_version_up: "5.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "6.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.3", test_version_up: "6.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

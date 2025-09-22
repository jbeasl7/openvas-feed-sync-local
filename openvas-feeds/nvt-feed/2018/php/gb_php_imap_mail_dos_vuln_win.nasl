# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108506");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2018-12-10 15:59:23 +0100 (Mon, 10 Dec 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:03:00 +0000 (Mon, 29 Aug 2022)");

  script_cve_id("CVE-2018-19935");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.x < 5.6.39, 7.x < 7.0.33, 7.1.x < 7.1.26, 7.2.x < 7.2.14 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference and application crash via an empty
  string occurs in the message argument to the imap_mail function of ext/imap/php_imap.c.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
  of service of the affected application.");

  script_tag(name:"affected", value:"PHP versions 5.x before 5.6.39, 7.0.x before 7.0.33, 7.1.x
  before 7.1.26 and 7.2.x before 7.2.14.");

  script_tag(name:"solution", value:"Update to version 5.6.39, 7.0.33, 7.1.26, 7.2.14, 7.3.0 or
  later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106143");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.6.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

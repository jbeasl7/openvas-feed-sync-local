# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154870");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-04 03:15:02 +0000 (Fri, 04 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-22 17:04:53 +0000 (Tue, 22 Jul 2025)");

  script_cve_id("CVE-2025-1220", "CVE-2025-1735", "CVE-2025-6491");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.1.33, 8.2.x < 8.2.29, 8.3.x < 8.3.23, 8.4.x < 8.4.10 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_php_smb_login_detect.nasl",
                      "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-1220: Null byte termination in hostnames

  - CVE-2025-1735: pgsql extension does not check for errors during escaping

  - CVE-2025-6491: NULL pointer dereference in PHP SOAP extension via large XML namespace prefix");

  script_tag(name:"affected", value:"PHP versions prior to 8.1.33, 8.2.x prior to 8.2.29, 8.3.x
  prior to 8.3.23 and 8.4.x prior to 8.4.10.");

  script_tag(name:"solution", value:"Update to version 8.1.33, 8.2.29, 8.3.23, 8.4.10 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.33");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.29");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.23");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.4.10");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3cr5-j632-f35r");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-hrwm-9436-5mv3");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-453j-q27h-5p8x");

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

if (version_is_less(version: version, test_version: "8.1.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

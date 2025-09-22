# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152368");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-06-07 03:46:50 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-10 12:50:06 +0000 (Mon, 10 Jun 2024)");

  script_cve_id("CVE-2024-4577", "CVE-2024-5458", "CVE-2024-5585", "CVE-2024-2408");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.1.29, 8.2.x < 8.2.20, 8.3.x < 8.3.8 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-4577: Argument injection in PHP-CGI (bypass of CVE-2012-1823)

  - CVE-2024-5458: Filter bypass in filter_var FILTER_VALIDATE_URL

  - CVE-2024-5585: Bypass of CVE-2024-1874

  - CVE-2024-2408: Marvin attack in OpenSSL on Windows builds");

  script_tag(name:"affected", value:"PHP prior to version 8.1.29, version 8.2.x through 8.2.19 and
  8.3.x through 8.3.7.");

  script_tag(name:"solution", value:"Update to version 8.1.29, 8.2.20, 8.3.8 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.29");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.20");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.8");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-hh26-4ppw-5864");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-9fcc-425m-g385");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-w8qr-v226-r27w");
  script_xref(name:"URL", value:"https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/");
  script_xref(name:"URL", value:"https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html");
  script_xref(name:"URL", value:"https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/");
  script_xref(name:"URL", value:"https://github.com/watchtowrlabs/CVE-2024-4577");
  script_xref(name:"URL", value:"https://people.redhat.com/~hkario/marvin/");
  script_xref(name:"URL", value:"https://blog.talosintelligence.com/new-persistent-attacks-japan/");
  script_xref(name:"URL", value:"https://www.bitdefender.com/en-us/blog/businessinsights/technical-advisory-update-mass-exploitation-cve-2024-4577");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_is_less(version: version, test_version: "8.1.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

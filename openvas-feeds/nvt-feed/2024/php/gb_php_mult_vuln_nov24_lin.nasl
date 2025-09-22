# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153495");
  script_version("2025-04-22T10:32:18+0000");
  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-11-21 14:28:00 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-24 01:15:04 +0000 (Sun, 24 Nov 2024)");

  script_cve_id("CVE-2024-8929", "CVE-2024-8932", "CVE-2024-11233", "CVE-2024-11234",
                "CVE-2024-11236");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.1.31, 8.2.x < 8.2.26, 8.3.x < 8.3.14 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_php_ssh_login_detect.nasl",
                      "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-8929: Leak partial content of the heap through heap buffer over-read

  - CVE-2024-8932: OOB access in ldap_escape

  - CVE-2024-11233: Single byte overread with convert.quoted-printable-decode filter

  - CVE-2024-11234: Configuring a proxy in a stream context might allow for CRLF injection in URIs

  - CVE-2024-11236: Integer overflow in the firebird/dblib quoter causing OOB writes

  - No CVE: Heap-Use-After-Free in sapi_read_post_data Processing in CLI SAPI Interface");

  script_tag(name:"affected", value:"PHP versions prior to 8.1.31, 8.2.x prior to 8.2.26 and 8.3.x
  prior to 8.3.14.");

  script_tag(name:"solution", value:"Update to version 8.1.31, 8.2.26, 8.3.14 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.31");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.26");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.14");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-h35g-vwh6-m678");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-g665-fm4p-vhff");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-r977-prxv-hc43");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-c5f2-jwm7-mmq2");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-5hqh-c84r-qjcv");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-4w77-75f9-2c8w");
  script_xref(name:"URL", value:"https://thephp.foundation/blog/2025/04/10/php-core-security-audit-results/");
  script_xref(name:"URL", value:"https://ostif.org/php-audit-complete/");
  script_xref(name:"URL", value:"https://blog.quarkslab.com/security-audit-of-php-src.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/04/12/2");

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

if (version_is_less(version: version, test_version: "8.1.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

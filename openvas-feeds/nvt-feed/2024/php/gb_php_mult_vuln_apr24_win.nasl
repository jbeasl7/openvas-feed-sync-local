# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152119");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2024-04-15 04:52:59 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  # nb: CVE-2024-1874 is the programming language specific issue while CVE-2024-3566 is the CVE for
  # / about the underlying problem so both have been attached here.
  script_cve_id("CVE-2024-1874", "CVE-2024-3096", "CVE-2024-3566");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.1.28, 8.2.x < 8.2.18, 8.3.x < 8.3.6 Multiple Vulnerabilities (BatBadBut) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-1874, CVE-2024-3566: Command injection via array-ish $command parameter of proc_open
  even if bypass_shell option enabled. This flaw is dubbed 'BatBadBut'.

  - CVE-2024-3096: password_verify can erroneously return true, opening ATO risk");

  script_tag(name:"affected", value:"PHP prior to version 8.1.28, version 8.2.x through 8.2.17 and
  8.3.x through 8.3.5.");

  script_tag(name:"solution", value:"Update to version 8.1.28, 8.2.18, 8.3.6 or later.");

  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-pc52-254m-w9w7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-h746-cjrr-wfmr");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.28");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.18");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.6");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/123335");
  script_xref(name:"URL", value:"https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way");

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

if (version_is_less(version: version, test_version: "8.1.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

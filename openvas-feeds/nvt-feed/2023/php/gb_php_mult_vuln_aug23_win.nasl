# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170530");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2023-08-04 11:52:17 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-21 16:31:00 +0000 (Mon, 21 Aug 2023)");

  script_cve_id("CVE-2023-3823", "CVE-2023-3824");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.0.30, 8.1.x < 8.1.22, 8.2.x < 8.2.9 Security Update - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-3823: Fixed bug GHSA-3qrf-m4j2-pcrr (Security issue with external entity loading in XML
  without enabling it)

  - CVE-2023-3824: Fixed bug GHSA-jqcx-ccgc-xwhv (Buffer mismanagement in phar_dir_read())");

  script_tag(name:"affected", value:"PHP prior to version 8.0.30, 8.1.x prior to 8.1.22 and 8.2.x
  prior to 8.2.9.");

  script_tag(name:"solution", value:"Update to version 8.0.30, 8.1.22, 8.2.9 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.22");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.30");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.9");
  # Note: Both advisories currently only mention < 8.0.30 as affected and 8.0.30 as fixed but the
  # linked changelogs above also shows that fixes got introduced in 8.1.22 and 8.2.9.
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3qrf-m4j2-pcrr");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-jqcx-ccgc-xwhv");

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

if (version_is_less(version: version, test_version: "8.0.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

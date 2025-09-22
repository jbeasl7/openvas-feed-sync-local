# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145959");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-05-17 07:04:11 +0000 (Mon, 17 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 21:08:00 +0000 (Tue, 01 Dec 2020)");

  script_cve_id("CVE-2020-26216", "CVE-2020-26227", "CVE-2020-26228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2020-009, TYPO3-CORE-SA-2020-010, TYPO3-CORE-SA-2020-011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-26216: Cross-site scripting (XSS) through Fluid view helper arguments

  - CVE-2020-26227: Cross-site scripting (XSS) in Fluid view helpers

  - CVE-2020-26228: Cleartext storage of session identifier");

  script_tag(name:"affected", value:"TYPO3 version 6.2.0 through 6.2.53, 7.6.0 through 7.6.47, 8.7.0
  through 8.7.37, 9.0.0 through 9.5.22 and 10.0.0 through 10.4.9.");

  script_tag(name:"solution", value:"Update to version 6.2.54, 7.6.48, 8.7.38, 9.5.23, 10.4.10 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-009");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-010");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-011");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "6.2.0", test_version2: "6.2.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.6.0", test_version2: "7.6.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.48", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.7.0", test_version2: "8.7.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

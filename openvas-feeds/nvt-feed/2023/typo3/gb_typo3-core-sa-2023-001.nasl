# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127328");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-02-08 06:04:22 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 16:38:00 +0000 (Thu, 16 Feb 2023)");

  script_cve_id("CVE-2023-24814");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 XSS Vulnerability (TYPO3-core-sa-2023-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TYPO3 core component GeneralUtility::getIndpEnv() uses
  the unfiltered server environment variable PATH_INFO, which allows attackers to inject malicious
  content.");

  script_tag(name:"affected", value:"TYPO3 version 8.7.x through 8.7.50 ELTS, 9.x prior to 9.5.39
  ELTS, 10.x prior to 10.4.34 ELTS, 11.x through 11.5.22 and 12.x through 12.1.3.");

  script_tag(name:"solution", value:"Update to version 8.7.51 ELTS, 9.5.40 ELTS, 10.4.36 LTS,
  11.5.23 LTS, 12.2.0 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2023-001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+" ) ) # nb: Version might not be exact enough
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "8.7.0", test_version2: "8.7.50" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.7.51", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.0.0", test_version2: "9.5.39" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.40", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.0.0", test_version2: "10.4.34" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.36", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "11.0.0", test_version2: "11.5.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.5.23", install_path: location );
  security_message( port: port, data: report);
  exit( 0 );
}

if( version_in_range( version: version, test_version: "12.0.0", test_version2: "12.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.2.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

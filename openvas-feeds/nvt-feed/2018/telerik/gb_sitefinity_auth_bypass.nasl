# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:progress:sitefinity";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113078");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-01-10 14:49:50 +0100 (Wed, 10 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-01 19:53:00 +0000 (Thu, 01 Feb 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15883");

  script_name("Sitefinity Authentication Bypass Vulnerability (Jan 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sitefinity_http_detect.nasl");
  script_mandatory_keys("sitefinity/detected");

  script_tag(name:"summary", value:"Sitefinity allows remote attackers to bypass authentication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to weak cryptography.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain privileges
  or cause a denial of service on load balanced sites.");

  script_tag(name:"affected", value:"Sitefinity versions 5.1.x, 5.2.x, 5.3.x, 5.4.x, 6.x, 7.x, 8.x,
  9.x and 10.x");

  script_tag(name:"solution", value:"Update to version 5.1.3460.0, 5.2.3810.0., 5.3.3930.0,
  5.4.4050.0, 6.0.4220.0, 6.1.4710.0, 6.2.4920.0, 6.3.5040.0, 7.0.5130.0, 7.1.5230.0, 7.2.5340.0,
  7.3.5680.0, 8.0.5760.0, 8.1.5840.0, 8.2.5950.0, 9.0.6040.0, 9.1.6160.0, 10.0.6413.0, 10.1.6504.0
  or later.");

  script_xref(name:"URL", value:"https://knowledgebase.progress.com/articles/Article/Sitefinity-Security-Advisory-for-cryptographic-vulnerability-CVE-2017-15883");
  script_xref(name:"URL", value:"https://www.mnemonic.no/news/2017/vulnerability-finding-sitefinity-cms/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "5.1.0.0", test_version2: "5.1.3459.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.3460.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.2.0.0", test_version2: "5.2.3809.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.3810.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.3.0.0", test_version2: "5.3.3929.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3930.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.4.0.0", test_version2: "5.4.4049.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4.4050.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0.0", test_version2: "6.0.4219.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.4220.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.1.0.0", test_version2: "6.1.4709.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.1.4710.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.2.0.0", test_version2: "6.2.4919.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.2.4920.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.3.0.0", test_version2: "6.3.5039.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.5040.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0.0", test_version2: "7.0.5129.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.5130.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.1.0.0", test_version2: "7.1.5229.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.5230.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.2.0.0", test_version2: "7.2.5339.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.5340.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.3.0.0", test_version2: "7.3.5679.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.5680.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.0.0.0", test_version2: "8.0.5759.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.5760.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.1.0.0", test_version2: "8.1.5839.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.1.5840.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.2.0.0", test_version2: "8.2.5949.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.5950.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.0.0.0", test_version2: "9.0.6039.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.6040.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.1.0.0", test_version2: "9.1.6159.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.1.6160.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.2.0.0", test_version2: "9.2.6249.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.2.6250.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.0.0.0", test_version2: "10.0.6412.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.6413.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.1.0.0", test_version2: "10.1.6503.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.1.6504.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113238");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-06-12 10:46:37 +0000 (Wed, 12 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-10 17:17:00 +0000 (Mon, 10 Jun 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12598", "CVE-2019-12600", "CVE-2019-12601");

  script_name("SuiteCRM 7.8.x < 7.8.30, 7.10.x < 7.10.17, 7.11.x < 7.11.5 Multiple SQL Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_suitecrm_http_detect.nasl");
  script_mandatory_keys("salesagility/suitecrm/detected");

  script_tag(name:"summary", value:"SuiteCRM is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive
  information and possibly execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"SuiteCRM versions 7.8.0 through 7.8.29, 7.10.0 through 7.10.16
  and 7.11.0 through 7.11.4.");

  script_tag(name:"solution", value:"Update to version 7.8.30, 7.10.17 or 7.11.5 respectively.");

  script_xref(name:"URL", value:"https://docs.suitecrm.com/admin/releases/7.11.x/#_7_11_5");
  script_xref(name:"URL", value:"https://docs.suitecrm.com/admin/releases/7.10.x/#_7_10_17");
  script_xref(name:"URL", value:"https://docs.suitecrm.com/admin/releases/7.8.x/#_7_8_30");

  exit(0);
}

CPE = "cpe:/a:salesagility:suitecrm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "7.8.0", test_version2: "7.8.29" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.8.30", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.10.0", test_version2: "7.10.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.10.17", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.11.0", test_version2: "7.11.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.11.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113791");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-02-24 08:47:49 +0000 (Wed, 24 Feb 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 15:01:00 +0000 (Wed, 09 Jun 2021)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-20229");

  script_name("PostgreSQL < 9.5.25, 9.6.x < 9.6.21, 10.x < 10.16, 11.x < 11.11, 12.x < 12.6, 13.x < 13.2 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user with SELECT privileges on a single column
  can craft a specific query to read all information from all columns of the table.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  read sensitive information.");

  script_tag(name:"affected", value:"PostgreSQL through version 9.5.24 and versions 9.6.0 through 9.6.20, 10.0 through 10.15,
  11.0 through 11.10, 12.0 through 12.6 and 13.0 through 13.1.");

  script_tag(name:"solution", value:"Update to version 9.5.25, 9.6.21, 10.16, 11.11, 12.6 or 13.2 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925296");

  exit(0);
}

CPE = "cpe:/a:postgresql:postgresql";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "9.5.25" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.25", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.6.0", test_version2: "9.6.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.6.21", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.0", test_version2: "10.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.16", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "11.0", test_version2: "11.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.11", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "12.0", test_version2: "12.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "13.0", test_version2: "13.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

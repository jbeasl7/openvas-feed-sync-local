# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:automattic:jetpack";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131064");
  script_version("2024-11-15T15:55:05+0000");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-13 09:08:03 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress JetPack Plugin Information Disclosure Vulnerability (Oct 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/jetpack/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'JetPack' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The Jetpack Contact Form feature allows any logged-in users on
  a site to read forms submitted by visitors on the site.");

  script_tag(name:"affected", value:"See the referenced vendor advisory.");

  script_tag(name:"solution", value:"See the referenced vendor advisory.");

  script_xref(name:"URL", value:"https://jetpack.com/blog/jetpack-13-9-1-critical-security-update/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "3.9.9", test_version_up: "3.9.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.0.0", test_version_up: "4.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1.0", test_version_up: "4.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.2.0", test_version_up: "4.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.3.0", test_version_up: "4.3.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.4.0", test_version_up: "4.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.5.0", test_version_up: "4.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.6.0", test_version_up: "4.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.7.0", test_version_up: "4.7.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.7.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.8.0", test_version_up: "4.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.8.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.9.0", test_version_up: "4.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.0.0", test_version_up: "5.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.1.0", test_version_up: "5.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.2.0", test_version_up: "5.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.3.0", test_version_up: "5.3.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.4.0", test_version_up: "5.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.5.0", test_version_up: "5.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.5.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.6.0", test_version_up: "5.6.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.6.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.7.0", test_version_up: "5.7.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.7.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.8.0", test_version_up: "5.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.9.0", test_version_up: "5.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.0.0", test_version_up: "6.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.1.0", test_version_up: "6.1.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.1.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.2.0", test_version_up: "6.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.3.0", test_version_up: "6.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.4.0", test_version_up: "6.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.5.0", test_version_up: "6.5.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.6.0", test_version_up: "6.6.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.6.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.7.0", test_version_up: "6.7.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.7.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.8.0", test_version_up: "6.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.8.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.9.0", test_version_up: "6.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.0.0", test_version_up: "7.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.1.0", test_version_up: "7.1.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.2.0", test_version_up: "7.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.3.0", test_version_up: "7.3.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.4.0", test_version_up: "7.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.5.0", test_version_up: "7.5.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.5.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.6.0", test_version_up: "7.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.7.0", test_version_up: "7.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.7.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.8.0", test_version_up: "7.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.8.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.9.0", test_version_up: "7.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.0.0", test_version_up: "8.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.1.0", test_version_up: "8.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.2.0", test_version_up: "8.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.3.0", test_version_up: "8.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.3.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.4.0", test_version_up: "8.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.5.0", test_version_up: "8.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.6.0", test_version_up: "8.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.7.0", test_version_up: "8.7.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.7.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.8.0", test_version_up: "8.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.8.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "8.9.0", test_version_up: "8.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.0.0", test_version_up: "9.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.1.0", test_version_up: "9.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.2.0", test_version_up: "9.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.3.0", test_version_up: "9.3.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.3.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.4.0", test_version_up: "9.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.5.0", test_version_up: "9.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.6.0", test_version_up: "9.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.7.0", test_version_up: "9.7.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.7.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.8.0", test_version_up: "9.8.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.8.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.9.0", test_version_up: "9.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.0.0", test_version_up: "10.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.1.0", test_version_up: "10.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.1.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.2.0", test_version_up: "10.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.3.0", test_version_up: "10.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.3.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.4.0", test_version_up: "10.4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.4.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.5.0", test_version_up: "10.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.6.0", test_version_up: "10.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.7.0", test_version_up: "10.7.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.7.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.8.0", test_version_up: "10.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.8.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.9.0", test_version_up: "10.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.0.0", test_version_up: "11.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.1.0", test_version_up: "11.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.2.0", test_version_up: "11.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.3.0", test_version_up: "11.3.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.3.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.4.0", test_version_up: "11.4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.4.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.5.0", test_version_up: "11.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.6.0", test_version_up: "11.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.7.0", test_version_up: "11.7.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.7.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.8.0", test_version_up: "11.8.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.8.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.9.0", test_version_up: "11.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.9.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.0.0", test_version_up: "12.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.1.0", test_version_up: "12.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.1.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.2.0", test_version_up: "12.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.3.0", test_version_up: "12.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.3.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.4.0", test_version_up: "12.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.5.0", test_version_up: "12.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.5.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.6.0", test_version_up: "12.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.6.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.7.0", test_version_up: "12.7.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.7.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.8.0", test_version_up: "12.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.8.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.9.0", test_version_up: "12.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.0.0", test_version_up: "13.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.1.0", test_version_up: "13.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.2.0", test_version_up: "13.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.3.0", test_version_up: "13.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.3.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.4.0", test_version_up: "13.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.5.0", test_version_up: "13.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.5.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.6.0", test_version_up: "13.6.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.6.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.7.0", test_version_up: "13.7.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.7.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.8.0", test_version_up: "13.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.8.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.9.0", test_version_up: "13.9.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.9.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

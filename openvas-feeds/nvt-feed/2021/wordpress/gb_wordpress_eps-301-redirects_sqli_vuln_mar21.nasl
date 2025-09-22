# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webfactoryltd:301_redirects";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113806");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-03-22 12:19:44 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-22 19:44:00 +0000 (Mon, 22 Mar 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-24142");

  script_name("WordPress 301 Redirects - Easy Redirect Manager Plugin < 2.51 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/eps-301-redirects/detected");

  script_tag(name:"summary", value:"The WordPress plugin '301 Redirects - Easy Redirect Manager'
  is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitize its 'Redirect From' column when
  importing a CSV file, allowing high privilege users to perform SQLi.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  read or manipulate sensitive information.");

  script_tag(name:"affected", value:"WordPress 301 Redirects - Easy Redirect Manager plugin through
  version 2.50.");

  script_tag(name:"solution", value:"Update to version 2.51 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/19800898-d7b6-4edd-887b-dac3c0597f14");

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

if( version_is_less( version: version, test_version: "2.51" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.51", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113183");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-05-09 13:16:19 +0200 (Wed, 09 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2641");

  script_name("Moodle 2.x / 3.x Remote Code Execution Vulnerability (Mar 2017) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle is prone to an authenticated remote code execution (RCE)
  vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Remote Code Execution is made possible by a combination of

  - insufficiently restrictive administrator dashboard

  - PHP Object Injection Vulnerability

  - SQL Injection Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation could allow an authenticated attacker to
  take complete control over the target system.");
  script_tag(name:"affected", value:"Moodle versions through 2.7.18, 2.8.0 through 3.0.8, 3.1.0 through 3.1.4
  and 3.2.0 through 3.2.1.");
  script_tag(name:"solution", value:"Update to version 2.7.19, 3.0.9, 3.1.5 or 3.2.2 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=349419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96977");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port: port, cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version: version, test_version: "2.7.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.19", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "3.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.9", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.5", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.2", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

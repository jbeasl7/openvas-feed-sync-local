# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127330");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-08 12:00:09 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 04:16:00 +0000 (Thu, 23 Feb 2023)");

  script_cve_id("CVE-2023-25727");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin 4.3.x < 4.9.11, 5.2.x < 5.2.1 XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user can trigger a cross-site scripting (XSS)
  attack by uploading a specially-crafted .sql file through the drag-and-drop interface.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.3.x through 4.9.10 and
  5.2.x prior to 5.2.1.");

  script_tag(name:"solution", value:"Update to version 4.9.11, 5.2.1 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2023-1/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port(cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "4.3.0", test_version_up: "4.9.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.9.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.2", test_version_up: "5.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

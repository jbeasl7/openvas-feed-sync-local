# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108515");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-12-12 07:54:53 +0100 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 14:10:00 +0000 (Mon, 22 Apr 2019)");
  script_cve_id("CVE-2018-19969");
  script_name("phpMyAdmin 4.7.0 <= 4.7.6, 4.8.0 <= 4.8.3 XSRF/CSRF Vulnerability (PMASA-2018-7) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-7/");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an cross-site ccripting (XSS) and cross-
  site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By deceiving a user to click on a crafted URL, it is possible to
  perform harmful SQL operations such as renaming databases, creating new tables/routines, deleting
  designer pages, adding/deleting users, updating user passwords, killing SQL processes, etc.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.7.0 through 4.7.6 and 4.8.0 through 4.8.3.");

  script_tag(name:"solution", value:"Update to version 4.8.4.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"4.7.0", test_version2:"4.7.6" ) ||
    version_in_range( version:vers, test_version:"4.8.0", test_version2:"4.8.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.8.4", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108212");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-08-16 12:18:02 +0200 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2012-4345", "CVE-2012-4579");
  script_name("phpMyAdmin Multiple XSS Vulnerabilities (Aug 2012) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2012-4/");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin versions 3.5.x before 3.5.2.2");

  script_tag(name:"solution", value:"Update to version 3.5.2.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^3\.5\." ) {
  if( version_is_less( version:vers, test_version:"3.5.2.2" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.2.2" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

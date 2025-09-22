# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111075");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2015-2206");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-01-16 07:00:00 +0100 (Sat, 16 Jan 2016)");
  script_name("phpMyAdmin 'libraries/select_lang.lib.php' Information Disclosure Vulnerability (PMASA-2015-1)");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"libraries/select_lang.lib.php includes invalid
  language values in unknown-language error responses that contain a CSRF token and
  may be sent with HTTP compression");

  script_tag(name:"impact", value:"Successfully exploiting this issue makes it easier
  for remote attackers to conduct a BREACH attack and determine this token via a series
  of crafted requests.");

  script_tag(name:"affected", value:"phpMyAdmin versions  4.0.x before 4.0.10.9,
  4.2.x before 4.2.13.2, and 4.3.x before 4.3.11.1");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin 4.0.10.9 or newer,
  or 4.2.13.2 or newer, or 4.3.11.1 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72949");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2015-1/");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"4.0.0", test_version2:"4.0.10.8" ) ) {
  fix = "4.0.10.9";
  VULN = TRUE;
}
if( version_in_range( version:vers, test_version:"4.2.0", test_version2:"4.2.13.1" ) ) {
  fix = "4.2.13.2";
  VULN = TRUE;
}
if( version_in_range( version:vers, test_version:"4.3.0", test_version2:"4.3.11.0" ) ) {
  fix = "4.3.11.1";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

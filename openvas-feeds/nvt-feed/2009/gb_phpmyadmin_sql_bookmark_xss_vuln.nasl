# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800595");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2284");
  script_name("phpMyAdmin SQL bookmark XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35649");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35543");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-5.php");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause XSS attacks and
  inject malicious web script or HTML code via a crafted SQL bookmarks.");

  script_tag(name:"affected", value:"phpMyAdmin version 3.0.x to 3.2.0.rc1.");

  script_tag(name:"insight", value:"This flaw arises because the input passed into SQL bookmarks is not
  adequately sanitised before using it in dynamically generated content.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 3.2.0.1 or later.");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

vers = ereg_replace( pattern:"-", string:vers, replace:"." );

if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.2.0.rc1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.0.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

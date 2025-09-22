# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103076");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-02-15 13:44:44 +0100 (Tue, 15 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0986", "CVE-2011-0987");
  script_name("phpMyAdmin Bookmark Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46359");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-2.php");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows a remote attacker to bypass
  certain security restrictions and perform unauthorized actions.");
  script_tag(name:"affected", value:"Versions prior to phpMyAdmin 3.3.9.2 and 2.11.11.3 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"phpMyAdmin is prone to a security bypass vulnerability that affects
  bookmarks.");

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

if( vers =~ "^3\." ) {
  if( version_is_less( version:vers, test_version:"3.3.9.2" ) ) {
    VULN = TRUE;
    fix = "3.3.9.2";
  }
} else if(vers =~ "^2\.") {
  if( version_is_less( version:vers, test_version:"2.11.11.3" ) ) {
    VULN = TRUE;
    fix = "2.11.11.3";
  }
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

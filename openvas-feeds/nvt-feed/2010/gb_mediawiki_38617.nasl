# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100535");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2010-1190");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("MediaWiki 1.15.0 - 1.15.1 'thumb.php' Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38617");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-March/000088.html");

  script_tag(name:"summary", value:"MediaWiki is prone to a security bypass vulnerability because it
  fails to properly restrict access to restricted content.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass intended security
  measures to view restricted content in private wikis.");

  script_tag(name:"affected", value:"MediaWiki versions 1.15.x prior to 1.15.2.");

  script_tag(name:"solution", value:"Update to version 1.15.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"1.15.0", test_version2:"1.15.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.15.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

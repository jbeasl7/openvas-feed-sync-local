# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900469");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2009-0737");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("MediaWiki 1.6.x < 1.6.12, 1.12.x < 1.12.4, 1.13.x < 1.13.4 Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33881");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33681");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0368");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are caused as the data supplied by the user via
  unspecified vectors is not adequately sanitised before being passed into the file
  'config/index.php' of MediaWiki.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker include arbitrary
  HTML or web scripts in the scope of the browser. This may lead to cross site scripting attacks and
  the attacker may gain sensitive information of the remote user or of the web application.");

  script_tag(name:"affected", value:"MediaWiki versions 1.6.x prior to 1.6.12, 1.12.x prior to
  1.12.4 and 1.13.x prior to 1.13.4.");

  script_tag(name:"solution", value:"Update to version 1.6.12, 1.12.4, 1.13.4 or later.");

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

if( version_in_range( version:vers, test_version:"1.13", test_version2:"1.13.3" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.3" ) ||
    version_in_range( version:vers, test_version:"1.6", test_version2:"1.6.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.13.4, 1.12.4 or 1.6.12" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

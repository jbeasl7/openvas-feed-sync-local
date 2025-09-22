# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800982");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2009-4589");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("MediaWiki 1.14.0, 1.15.0 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35662");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51687");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2009-July/000087.html");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.14/mediawiki-1.14.1.patch.gz");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.15/mediawiki-1.15.1.patch.gz");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.14/mediawiki-1.14.1.tar.gz");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.15/mediawiki-1.15.1.tar.gz");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the error in 'Special:Block' script in the
  'getContribsLink' function in 'SpecialBlockip.php' page. It fails to properly sanitize user
  supplied input while processing the 'ip' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  arbitrary HTML or web scripts in the scope of the browser and allows to obtain sensitive
  information.");

  script_tag(name:"affected", value:"MediaWiki versions 1.14.0 and 1.15.0 only.");

  script_tag(name:"solution", value:"Update to version 1.14.1, 1.15.1 or later.");

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

if( version_is_equal( version:vers, test_version:"1.14.0" ) ||
    version_is_equal( version:vers, test_version:"1.15.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.14.1 or 1.15.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

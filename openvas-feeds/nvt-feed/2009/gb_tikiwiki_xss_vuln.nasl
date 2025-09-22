# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800266");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-1204");

  script_name("Tiki Wiki CMS Groupware < 2.4 Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tiki/wiki/http/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitization of user
  supplied input in the pages i.e. 'tiki-orphan_pages.php', 'tiki-listpages.php',
  'tiki-list_file_gallery.php' and 'tiki-galleries.php' which lets the attacker conduct XSS attacks
  inside the context of the web application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary HTML codes in the context of the affected web application.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 2.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34273");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34105");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34106");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34107");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34108");
  script_xref(name:"URL", value:"http://info.tikiwiki.org/tiki-read_article.php?articleId=51");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# Multiple XSS attempts
urls = make_list( dir + '/tiki-listpages.php/<script>alert("XSS_Check");</script>',
                  dir + '/tiki-galleries.php/<script>alert("XSS_Check");</script>',
                  dir + '/tiki-orphan_pages.php/<script>alert("XSS_Check");</script>',
                  dir + '/tiki-list_file_gallery.php/<script>alert("XSS_Check");</script>' );

foreach url( urls ) {
  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'<script>alert\\("XSS_Check"\\);</script>' ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801877");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2010-2788");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("MediaWiki < 1.15.5 'profileinfo.php' XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/http/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=620225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42024");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=620226");
  script_xref(name:"URL", value:"http://svn.wikimedia.org/viewvc/mediawiki?view=revision&revision=69984");
  script_xref(name:"URL", value:"http://svn.wikimedia.org/viewvc/mediawiki?view=revision&revision=69952");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'filter' parameter to profileinfo.php, which allows attackers to execute arbitrary
  HTML and script code on the web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.15.5.");

  script_tag(name:"solution", value:"Update to version 1.15.5, 1.16.0 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + '/profileinfo.php?filter="><script>alert(document.cookie)</script>';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"><script>alert\(document\.cookie\)</script>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103392");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-01-19 12:05:58 +0100 (Thu, 19 Jan 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpVideoPro <= 0.9.7 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"phpVideoPro is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This can
  allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"phpVideoPro version 0.9.7 and probably prior.");

  script_tag(name:"solution", value:"See the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51428");
  script_xref(name:"URL", value:"http://code.google.com/p/simplesamlphp/issues/detail?id=468");
  script_xref(name:"URL", value:"http://code.google.com/p/simplesamlphp/source/detail?r=3009");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/phpvideopro", "/video", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  url = dir + "/medialist.php";

  if( http_vuln_check( port:port, url:url, pattern:"<Title>phpVideoPro", usecache:TRUE ) ) {
    url = dir + '/medialist.php/"><script>alert(/xss-test/)</script>/';

    if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/xss-test/\)</script>",
                         check_header:TRUE ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

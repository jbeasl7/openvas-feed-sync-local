# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18375");
  script_version("2024-05-07T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2005-1782", "CVE-2005-1783");
  script_name("BookReview beta 1.0 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://lostmon.blogspot.com/2005/05/bookreview-10-multiple-variable-xss.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121163910/http://www.securityfocus.com/bid/13783");
  script_xref(name:"OSVDB", value:"16871");
  script_xref(name:"OSVDB", value:"16872");
  script_xref(name:"OSVDB", value:"16873");
  script_xref(name:"OSVDB", value:"16874");
  script_xref(name:"OSVDB", value:"16875");
  script_xref(name:"OSVDB", value:"16876");
  script_xref(name:"OSVDB", value:"16877");
  script_xref(name:"OSVDB", value:"16878");
  script_xref(name:"OSVDB", value:"16879");
  script_xref(name:"OSVDB", value:"16880");
  script_xref(name:"OSVDB", value:"16881");

  script_tag(name:"summary", value:"BookReview is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2005-1782: Multiple cross-site scripting (XSS) vulnerabilities

  - CVE-2005-1783: Information disclosure vulnerability");

  script_tag(name:"affected", value:"BookReview version beta 1.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/add_url.htm";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "Powered by BookReview" )
    continue;

  url = dir + "/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('XSS'\)</script>", extra_check:"Powered by BookReview", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

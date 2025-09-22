# SPDX-FileCopyrightText: 2006 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19692");
  script_version("2024-04-19T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-04-19 15:38:40 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2392");
  script_xref(name:"OSVDB", value:"18128");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CMSimple 'index.php?search' XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2005/07/cmsimple-search-variable-xss.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210206123540/http://www.securityfocus.com/bid/14346");
  script_xref(name:"URL", value:"http://www.cmsimple.dk/forum/viewtopic.php?t=2470");

  script_tag(name:"summary", value:"CMSimple is prone to cross-site scripting (XSS) attacks due to
  its failure to sanitize user-supplied input to the search field.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Updates are available. See the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("url_func.inc");
include("misc_func.inc");

vtstrings = get_vt_strings();

xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
exss = urlencode( str:xss );

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "cmsimple" )
    continue;

  url = dir + "/index.php?search=" + exss + "&function=search";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && xss >< res &&
      ( egrep( string:res, pattern:'meta name="generator" content="CMSimple .+ cmsimple\\.dk' ) ||
        egrep( string:res, pattern:'href="http://www\\.cmsimple\\.dk/".+>Powered by CMSimple<' ) ||
        egrep( string:res, pattern:string('href="', dir, '/\\?&(sitemap|print)">' ) ) ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );

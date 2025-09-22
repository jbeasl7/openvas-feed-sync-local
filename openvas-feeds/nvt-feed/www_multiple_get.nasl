# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18366");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Several GET locks web server");
  # It is not really destructive, but it is useless in safe_checks mode
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote web server shuts down temporarily or blacklists
  us when it receives several GET HTTP/1.0 requests in a row.

  This might trigger false positive in generic destructive or DoS plugins.

  The scanner enabled some countermeasures, however they might be
  insufficient.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

# CISCO IP Phone 7940 behaves correctly on a HTTP/1.1 request,
# so we forge a crude HTTP/1.0 request.

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

host = http_host_name( port:port );

req = string( "GET / HTTP/1.0\r\n",
              "Host: ", host, "\r\n" );
max = 12;

for( i = 0; i < max; i++ ) {
  recv = http_send_recv( port:port, data:req );
  if( ! recv )
    break;
}

if( i == 0 ) {
  # nb: Server is dead?
} else if( i < max ) {
  set_kb_item( name:'www/multiple_get/' + port, value:i );
  log_message( port:port );
  exit( 0 );
}

exit( 99 );

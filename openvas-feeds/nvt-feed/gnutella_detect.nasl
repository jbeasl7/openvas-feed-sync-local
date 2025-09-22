# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10946");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Gnutella Servent Detection (Gnutella, HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Product detection");
  # nb: No need to add a dependency to "httpver.nasl" as this isn't a HTTP server.
  script_dependencies("find_service.nasl");
  # Gnutella servent _might_ be detected as a web server
  script_require_ports("Services/www", "Services/unknown", 6346);

  script_tag(name:"summary", value:"Gnutella protocol and HTTP based detection of Gnutella
  'servent'.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("http_func.inc");

ports = unknownservice_get_ports( default_port_list:make_list( 6346 ) ); # Detection is commented out in nasl_builtin_find_service.c

foreach port( ports ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket:soc, data:'GNUTELLA CONNECT/0.4\r\n\r\n' );
    answer = recv( socket:soc, length:500 );
    close( soc );

    if( "GNUTELLA OK" >< answer ) {
      log_message( port:port );
      service_register( port:port, proto:"gnutella" );
    }
  }
}

# Gnutella servent _might_ be detected as a web server
port = http_get_port( default:6346 );

banner = http_get_remote_headers( port:port );
if( ! banner ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    send( socket:soc, data:'GET / HTTP/1.0\r\n\r\n' );
    banner = http_recv( socket:soc );
    close( soc );
  } else {
    exit( 0 );
  }
}

# We should probably add more regex here. But there are 100+ Gnutella software
if( egrep( pattern:"Gnutella|BearShare", string:banner, icase:TRUE ) ) {
  report = "Although this service did not answer to Gnutella protocol 0.4, it might be a Gnutella server.";
  log_message( port:port, data:report );
}

exit( 0 );

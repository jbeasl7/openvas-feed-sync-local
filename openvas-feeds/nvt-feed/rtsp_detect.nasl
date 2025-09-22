# SPDX-FileCopyrightText: 2005 Alert4Web.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10762");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RTSP Server Type And Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Alert4Web.com");
  script_family("Service detection");
  script_dependencies("find_service5.nasl");
  script_require_ports("Services/rtsp", 554);

  script_tag(name:"summary", value:"Detection of the Real-Time Streaming Protocol (RTSP) Server's
  type and version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("sip.inc");

port = service_get_port( default:554, proto:"rtsp" );

# nb:
# - sip_construct_options_req() used below might fork on multiple hostnames and should be always
#   before the first open_sock_tcp() call
# - For simplicity within such an older detection we're just calling get_host_name() instead
#   directly here as it will also fork
get_host_name();

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

data = string( "OPTIONS * RTSP/1.0\r\n\r\n" );
send( socket:soc, data:data );
header = recv( socket:soc, length:1024 );
close( soc );

if( header =~ "^RTSP/1\.[0-9]+ " && ( "CSeq: " >< header || "Public: " >< header || "Server: " >< header ) ) {
  found = TRUE;
} else {

  # nb: Some RTSP services seems to no answer to the OPTIONS probe above and in find_service2.nasl
  # but answering to the SIP OPTIONS request (see find_service5.nasl as well).
  soc = open_sock_tcp( port );
  if( soc ) {
    data = sip_construct_options_req( port:port, proto:"tcp" );
    send( socket:soc, data:data );
    header = recv( socket:soc, length:1024 );
    close( soc );
    if( header =~ "^RTSP/1\.[0-9]+ " && ( "CSeq: " >< header || "Public: " >< header || "Server: " >< header ) ) {
      found = TRUE;
    }
  }
}

if( found ) {

  service_register( proto:"rtsp", port:port );

  server = egrep( pattern:"Server:", string:header, icase:TRUE );
  auth   = egrep( pattern:"WWW-Authenticate:", string:header, icase:TRUE );

  if( server ) {
    server = chomp( server );
    set_kb_item( name:"RTSP/server_banner/available", value:TRUE );
    set_kb_item( name:"RTSP/server_or_auth_banner/available", value:TRUE );
    set_kb_item( name:"RTSP/" + port + "/server_banner", value:server );
    report = string( "The remote RTSP server is :\n\n", server, "\n\n" );
  }

  if( auth ) {
    auth = chomp( auth );
    set_kb_item( name:"RTSP/auth_banner/available", value:TRUE );
    set_kb_item( name:"RTSP/server_or_auth_banner/available", value:TRUE );
    set_kb_item( name:"RTSP/" + port + "/auth_banner", value:auth );
  }

  report += string( "All RTSP Header for 'OPTIONS *' method:\n\n", chomp( header ) );
  log_message( port:port, data:report );
}

exit( 0 );

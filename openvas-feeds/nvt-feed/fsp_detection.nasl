# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11987");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect FSP Compatible Hosts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Service detection");
  script_require_udp_ports(21, 2000, 2221);

  script_xref(name:"URL", value:"http://fsp.sourceforge.net/");

  script_tag(name:"summary", value:"The remote host is running a FSP (File Service Protocol)
  compatible product. FSP is a protocol designed to serve file on top of the UDP protocol.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

i = 0;

foreach port( make_list( 21, 2000, 2221 ) ) {

  i++;

  if( ! get_udp_port_state( port ) ) continue;

  # This is UDP based protocol ...
  udpsock = open_sock_udp( port );
  if( ! udpsock ) continue;
  data = raw_string( 0x10, 0x44, 0xF0, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  send( socket:udpsock, data:data );

  if( i == 1 ) {
    z = recv( socket:udpsock, length:1024 );
  } else {
    z = recv( socket:udpsock, length:1024, timeout:0 );
  }

  close( udpsock );

  if( z ) {
    if( z[0] == raw_string( 0x10 ) ) {
      mlen = ord( z[7] );
      Server = "";
      for( i = 0; i < mlen - 1; i++ ) {
        Server = string( Server, z[12+i] );
      }

      Server -= string( "\n" );
      if( ! get_kb_item( string( "fsp/banner/", port ) ) )
        set_kb_item( name:string( "fsp/banner/", port ), value:Server );
      set_kb_item( name:"fsp_compatible_host/identified", value:TRUE );

      report = "The remote sotware is : " + Server;
      log_message( port:port, data:report, protocol:"udp" );
      service_register( port:port, ipproto:"udp", proto:"fsp" );
      exit( 0 );
    }
  }
}

exit( 0 );
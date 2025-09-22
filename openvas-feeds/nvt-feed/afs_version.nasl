# SPDX-FileCopyrightText: 2005 CERN
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10441");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AFS client version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 CERN");
  script_family("Service detection");
  script_require_udp_ports(7001);

  script_tag(name:"summary", value:"This detects the AFS client version by connecting
  to the AFS callback port and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = 7001;
if( ! get_udp_port_state( port ) )
  exit( 0 );

sock = open_sock_udp( port );
if( ! sock )
  exit( 0 );

data = raw_string( 0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x0d, 0x05, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket:sock, data:data );
max = 80;
info = recv( socket:sock, length:max );
close( sock );

if( strlen( info ) > 28 ) {
  data = "AFS version: ";
  for( i = 28; i < max; i++ ) {
    if( info[i] == raw_string( 0x00 ) ) {
      i = max;
    } else {
      data += info[i];
    }
  }
  log_message( port:port, protocol:"udp", data:data );
}

exit( 0 );

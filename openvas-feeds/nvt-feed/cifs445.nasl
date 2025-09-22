# SPDX-FileCopyrightText: 2006 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11011");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMB/CIFS Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Renaud Deraison");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects whether port 445 and 139 are open and
  if they are running a CIFS/SMB server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("port_service_func.inc");
include("misc_func.inc");

flag = 0;
vt_strings = get_vt_strings();

# TODO: Check all unknown ports. At least Samba can listen on other ports...

if( get_port_state( 445 ) ) {

  soc = open_sock_tcp( 445 );
  if( soc ) {
    r = smb_neg_prot( soc:soc );
    close( soc );
    if( r ) {
      service_register( port:445, proto:"cifs" );
      log_message( port:445, data:"A CIFS server is running on this port" );
      set_kb_item( name:"SMB/transport", value:445 );
      flag = 1;
    }
  }
}

if( get_port_state( 139 ) ) {

  soc = open_sock_tcp( 139 );
  if( soc ) {
    nb_remote = netbios_name( orig:string( vt_strings["default_rand"] ) );
    nb_local  = netbios_redirector_name();
    session_request = raw_string( 0x81, 0x00, 0x00, 0x44 ) +
                      raw_string( 0x20 ) +
                      nb_remote +
                      raw_string( 0x00, 0x20 ) +
                      nb_local  +
                      raw_string( 0x00 );

    send( socket:soc, data:session_request );
    r = recv( socket:soc, length:4 );
    close( soc );
    if( r && ( ord(r[0] ) == 0x82 || ord( r[0] ) == 0x83 ) ) {
      service_register( port:139, proto:"smb" );
      log_message( port:139, data:"A SMB server is running on this port" );
      if( ! flag ) set_kb_item( name:"SMB/transport", value:139 );
    }
  }
}

exit( 0 );

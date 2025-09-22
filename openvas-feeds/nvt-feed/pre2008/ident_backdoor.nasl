# SPDX-FileCopyrightText: 2005 Brian Smith-Sweeney
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14841");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IRC bot ident server detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Brian Smith-Sweeney");
  script_family("Malware");
  script_require_ports("Services/auth", 113);
  script_dependencies("find_service1.nasl");

  script_tag(name:"solution", value:"re-install the remote system");

  script_tag(name:"summary", value:"This host seems to be running an ident server, but the ident server responds
  to an empty query with a random userid. This behavior may be indicative of an
  irc bot, worm, and/or virus infection. It is very likely this system has
  been compromised.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

# End user-defined variables; you should not have to touch anything below this
soc_out =   3; # Socket connect timeout; increase this for slow ident bots
soc_sleep = 5; # Time to wait between socket connections; increase this for bots
               # that don't respond to multiple requests in quick succession
r = '\r\n';    # Data to send to the auth server at initial connect

port = service_get_port( proto:"auth", default:113 );
if( ! get_port_state( port ) ) exit( 0 );

soc1 = open_sock_tcp( port );
if( ! soc1 ) exit(0);

if( send( socket:soc1, data:r ) <= 0 ) exit( 0 );

r1 = recv_line( socket:soc1, length:1024, timeout:soc_out );
ids1 = split( r1, sep:":" );

if( "USERID" >< ids1[1] ) {

  close( soc1 );
  sleep( soc_sleep );

  soc2 = open_sock_tcp( port );
  if( ! soc2 ) exit( 0 );

  send( socket:soc2, data:r );
  r2 = recv_line( socket:soc2, length:1024, timeout:soc_out );
  ids2 = split( r2, sep:":" );
  close( soc2 );

  if( "USERID" >< ids2[1] ) {

    if( ids1[3] == ids2[3] ) exit( 0 );

    security_message( port:port );

    if( service_is_unknown( port:port ) )
      set_kb_item( name:"fake_identd/" + port, value:TRUE );
      exit( 0 );
  }
} else {
  close( soc1 );
}

exit( 99 );

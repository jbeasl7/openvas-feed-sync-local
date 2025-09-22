# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108520");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-28 16:59:45 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Logitech SqueezeCenter/Media Server Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 3483);

  script_tag(name:"summary", value:"Detection of a Logitech SqueezeCenter/Media Server via UDP.

  This script sends an UDP discovery request to the target and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:3483, ipproto:"udp" );

soc = open_sock_udp( port );
if( ! soc )
  exit( 0 );

# https://github.com/Excito/squeezecenter/blob/master/Slim/Networking/Discovery/Server.pm
req  = "eIPAD" + raw_string( 0x00 );
req += "NAME" + raw_string( 0x00 );
req += "JSON" + raw_string( 0x00 );
req += "VERS" + raw_string( 0x00 );
req += "UUID" + raw_string( 0x00 );

send( socket:soc, data:req );
res = recv( socket:soc, length:512 );
close( soc );
if( ! res )
  exit( 0 );

#ENAME
#     hostnameJSON.9001VERS.7.7.2UUID$abcd-efgh-ijkl-mnop-qrst-uvwx-yz
if( res =~ "^ENAME.+JSON.[0-9]+VERS.*UUID\$.+" ) {

  version = "unknown";
  vers = eregmatch( string:res, pattern:"VERS.([0-9.]+)", icase:FALSE );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"logitech/squeezecenter/udp/" + port + "/concluded", value:vers[0] );
  }

  set_kb_item( name:"logitech/squeezecenter/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/udp/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/udp/port", value:port );
  set_kb_item( name:"logitech/squeezecenter/udp/" + port + "/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/udp/" + port + "/version", value:version );

  log_message( port:port, data:"A Logitech SqueezeCenter/Media Server service seems to be running on this port." );
  service_register( port:port, proto:"squeezecenter", ipproto:"udp", message:"A Logitech SqueezeCenter/Media Server service seems to be running on this port." );
}

exit( 0 );

# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11963");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SIP Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Service detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 5060);

  script_xref(name:"URL", value:"http://www.cs.columbia.edu/sip/");

  script_tag(name:"summary", value:"UDP based detection of services supporting the Session
  Initiation Protocol (SIP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("sip.inc");
include("misc_func.inc");

proto = "udp";

port = unknownservice_get_port( default:5060, ipproto:proto );
banner = sip_get_banner( port:port, proto:proto );

# nb: sip_get_banner is setting this banner if it has detected a SIP service.
if( ! full_banner = get_kb_item( "sip/full_banner/" + proto + "/" + port ) )
  exit( 0 );

if( banner ) {

  set_kb_item( name:"sip/banner/available", value:TRUE );
  serverbanner = get_kb_item( "sip/server_banner/" + proto + "/" + port );
  if( serverbanner )
    desc = "Server Banner: " + serverbanner;

  uabanner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
  if( uabanner ) {
    if( desc )
      desc += '\n';
    desc += "User-Agent: " + uabanner;
  }
}

options = get_kb_item( "sip/options_banner/" + proto + "/" + port );
if( options )
  desc += '\nSupported Options: ' + options;

desc += '\n\nFull banner output:\n\n' + full_banner;

set_kb_item( name:"sip/detected", value:TRUE );
set_kb_item( name:"sip/port_and_proto", value:port + "#-#" + proto );

log_message( port:port, protocol:proto, data:desc );
service_register( port:port, ipproto:proto, proto:"sip", message:"A service supporting the SIP protocol was identified." );

exit( 0 );

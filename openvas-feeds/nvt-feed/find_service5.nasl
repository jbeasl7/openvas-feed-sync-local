# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108203");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-08-04 09:08:04 +0200 (Fri, 04 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'SIP' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service4.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It sends a 'SIP OPTIONS' request to the remaining unknown services
  and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("sip.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

# nb: The sip functions are defaulting to "udp" if no proto: parameter is passed so setting "tcp" here
proto = "tcp";

# nb:
# - This is a request where a Zabbix Server is answering to. There might be other services out there
#   answering to such a SIP request so trying this as well for other unknown services.
# - sip_construct_options_req() is forking on multiple hostnames so it should be always before the
#   first sip_open_socket() call
req = sip_construct_options_req( port:port, proto:proto );

if( ! soc = sip_open_socket( port:port, proto:proto ) )
  exit( 0 );

send( socket:soc, data:req );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to a "SIP OPTIONS" request', "\n" );
  exit( 0 );
}

k = "FindService/tcp/" + port + "/sip";
set_kb_item( name:k, value:r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:hexstr( r ) );

rhexstr = hexstr( r );

# Fallback for the find_service1.nasl check if the service is only answering to SIP OPTIONS requests.
if( sip_verify_banner( data:r ) ) {
  service_register( port:port, proto:"sip", message:"A service supporting the SIP protocol was identified." );
  log_message( port:port, data:"A service supporting the SIP protocol was identified." );
  exit( 0 );
}

# nb: Check_MK Agent, find_service1.nasl should already do the job but sometimes the Agent behaves strange
# and only sends data too late. This is a fallback for such a case.
if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  # nb: Check_MK Agents seems to not answer to repeated requests in a short amount of time so saving the response here for later processing.
  replace_kb_item( name:"checkmk_agent/banner/" + port, value:r );
  service_register( port:port, proto:"checkmk_agent", message:"A Checkmk Agent seems to be running on this port." );
  log_message( port:port, data:"A Checkmk Agent seems to be running on this port." );
  exit( 0 );
}

# 0x00:  61 63 70 70 00 03 00 01 3A 47 07 FB 00 00 00 01    acpp....:G......
# 0x10:  00 00 00 00 31 38 30 2F 32 39 2E 32 32 35 2E 32    ....180/29.225.2
# 0x20:  FF FF FF FA 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x30:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x40:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x50:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x60:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x70:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
#
# or
#
# 0x00:  61 63 70 70 00 03 00 00 35 BC 07 F0 00 00 00 01    acpp....5.......
# 0x10:  00 00 00 00 31 36 30 2F 33 2E 31 34 2E 31 32 33    ....160/3.14.123
# 0x20:  FF FF FF FA 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x30:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x40:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x50:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x60:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x70:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
if( rhexstr =~ "^61637070000[0-9]000[0-9]" ) { # nb: The following parts seems to be randomly so just keep the check that short...
  service_register( port:port, proto:"airport-admin", message:"A Apple AirPort Admin service seems to be running on this port." );
  log_message( port:port, data:"A Apple AirPort Admin service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  70 02 77 61                                        p.wa
if( rhexstr =~ "^70027761$" ) {
  service_register( port:port, proto:"activemq_mqtt", message:"A ActiveMQ MQTT service seems to be running on this port." );
  log_message( port:port, data:"A ActiveMQ MQTT service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  52 54 53 50 2F 31 2E 30 20 32 30 30 20 4F 4B 0D    RTSP/1.0 200 OK.
# 0x10:  0A 43 53 65 71 3A 20 36 33 31 30 34 20 4F 50 54    .CSeq: 63104 OPT
# 0x20:  49 4F 4E 53 0D 0A 50 75 62 6C 69 63 3A 20 4F 50    IONS..Public: OP
# 0x30:  54 49 4F 4E 53 2C 20 44 45 53 43 52 49 42 45 2C    TIONS, DESCRIBE,
# 0x40:  20 50 4C 41 59 2C 20 50 41 55 53 45 2C 20 53 45     PLAY, PAUSE, SE
# 0x50:  54 55 50 2C 20 54 45 41 52 44 4F 57 4E 2C 20 53    TUP, TEARDOWN, S
# 0x60:  45 54 5F 50 41 52 41 4D 45 54 45 52 2C 20 47 45    ET_PARAMETER, GE
# 0x70:  54 5F 50 41 52 41 4D 45 54 45 52 0D 0A 44 61 74    T_PARAMETER..Dat
# 0x80:  65 3A 20 20 4D 6F 6E 2C 20 4A 75 6C 20 32 33 20    e:  Mon, Jul 23  # nb: ending space...
# 0x90:  32 30 31 38 20 31 37 3A 32 31 3A 31 38 20 47 4D    2018 17:21:18 GM
# 0xA0:  54 0D 0A 0D 0A                                     T....
#
# nb: Some RTSP services seems to no answer to the probes in find_service2.nasl
# but answering to the SIP request above.
if( r =~ "^RTSP/1\.[0-9]+" && ( "CSeq: " >< r || "Public: " >< r || "Server: " >< r ) ) {
  service_register( port:port, proto:"rtsp", message:"A streaming server seems to be running on this port." );
  log_message( port:port, data:"A streaming server seems to be running on this port." );
  exit( 0 );
}

# On 9300/tcp
# 0x00:  54 68 69 73 20 69 73 20 6E 6F 74 20 61 20 48 54    This is not a HT
# 0x10:  54 50 20 70 6F 72 74                               TP port
# See find_service1.nasl as well
if( r =~ "^This is not a HTTP port$" ) {
  service_register( port:port, proto:"elasticsearch", message:"An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
  log_message( port:port, data:"An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  4A 44 57 50 2D 48 61 6E 64 73 68 61 6B 65          JDWP-Handshake
# nb: Covered in various find_service*.nasl because the service seems to be unstable and
# we want to try our best to detect this service.
if( r == "JDWP-Handshake" ) {
  service_register( port:port, proto:"jdwp", message:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  log_message( port:port, data:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  exit( 0 );
}

# Juniper Junos OS JUNOScript (3221/tcp)
if( r =~ '^<\\?xml version="1\\.0" encoding="us-ascii"\\?>[^<]+<junoscript xmlns="http://xml\\.juniper\\.net' ) {
  service_register( port:port, proto:"junoscript", message:"Juniper Junos OS JUNOScript seems to be running on this port" );
  replace_kb_item( name:"juniper/junos/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"Juniper Junos OS JUNOScript seems to be running on this port" );
  exit( 0 );
}

# nb: See find_service_3digits.nasl and other find_service* as well
if( egrep( string:r, pattern:"^220 (HP|JetDirect) GGW server \(version ([0-9.]+)\) ready" ) ) {
  service_register( port:port, proto:"hp-gsg", message:"A Generic Scan Gateway (GGW) server service is running at this port." );
  log_message( port:port, data:"A Generic Scan Gateway (GGW) server service is running at this port." );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if( ! r0 ) unknown_banner_set( port:port, banner:r );

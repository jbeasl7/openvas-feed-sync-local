# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108204");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-08-04 09:08:04 +0200 (Fri, 04 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'BINARY' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service5.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It sends a 'BINARY' request to the remaining unknown services and
  tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("port_service_func.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 0x00, 0x01, 0x02, 0x03, 0x04 );
send( socket:soc, data:req );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to a "0x00, 0x01, 0x02, 0x03, 0x04" raw string request', "\n" );
  exit( 0 );
}

rhexstr = hexstr( r );

k = "FindService/tcp/" + port + "/bin";
set_kb_item( name:k, value:r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:rhexstr );

if( "rlogind: Permission denied." >< r ) {
  service_register( port:port, proto:"rlogin", message:"A rlogin service seems to be running on this port." );
  log_message( port:port, data:"A rlogin service seems to be running on this port." );
  exit( 0 );
}

if( "Where are you?" >< r ) {
  service_register( port:port, proto:"rexec", message:"A rexec service seems to be running on this port." );
  log_message( port:port, data:"A rexec service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  53 53 48 2D 32 2E 30 2D 6C 69 62 73 73 68 5F 30    SSH-2.0-libssh_0
# 0x10:  2E 37 2E 39 30 0D 0A                               .7.90..
# on e.g. TeamSpeak3 running on port 10022/tcp
#
# 0x00:  53 53 48 2D 32 2E 30 2D 6C 69 62 73 73 68 2D 30    SSH-2.0-libssh-0
# 0x10:  2E 35 2E 32 0A                                     .5.2.
#
# 0x00:  53 53 48 2D 32 2E 30 2D 6C 69 62 73 73 68 0A       SSH-2.0-libssh.
#
# nb:  Sometimes this isn't detected via find_service.nasl as SSH
# nb2: Keep in single quotes so that the "\r" and "\n" are matching...
if( r =~ '^SSH-2.0-libssh[_-][0-9.]+[^\\r\\n]+$' ||
    r == 'SSH-2.0-libssh\n' ) {
  service_register( port:port, proto:"ssh", message:"A SSH service seems to be running on this port." );
  log_message( port:port, data:"A SSH service seems to be running on this port." );
  # nb3: Neither ssh_detect.nasl nor get_ssh_banner() is sometimes able to get the text
  # banner above so set the SSH banner manually here...
  replace_kb_item( name:"SSH/server_banner/" + port, value:chomp( r ) );
  exit( 0 );
}

# 0x00:  00 11 49 6E 76 61 6C 69 64 20 63 6F 6D 6D 61 6E    ..Invalid comman
# 0x10:  64 0A 00 00 00                                     d....
if( rhexstr == "0011496e76616c696420636f6d6d616e640a000000" ) {
  service_register( port:port, proto:"apcupsd", message:"A apcupsd service seems to be running on this port." );
  log_message( port:port, data:"A apcupsd service seems to be running on this port." );
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

# 0x00:  01 39 39 39 39 46 46 31 42 03                      .9999FF1B.
#
# nb: See find_service1.nasl as well
#
# nb: The last digit is the EXT char which defaults to 0x03 but can be changed on some devices according to the vendor documentation.
if( rhexstr =~ "013939393946463142.." ) {
  service_register( port:port, proto:"automated-tank-gauge", message:"A Automated Tank Ggauge (ATG) service seems to be running on this port." );
  log_message( port:port, data:"A Automated Tank Gauge (ATG) service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  31 00                                              1.
# https://www.veritas.com/support/en_US/article.100002391
if( port == 13724 && rhexstr == "3100" ) {
  service_register( port:port, proto:"vnetd", message:"A Veritas Network Utility service seems to be running on this port." );
  log_message( port:port, data:"A Veritas Network Utility service seems to be running on this port." );
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

# Jenkins CLI (50000/tcp) or possible some other random "high" port
#
# 0x00:  55 6E 72 65 63 6F 67 6E 69 7A 65 64 20 70 72 6F    Unrecognized pro
# 0x10:  74 6F 63 6F 6C 3A 20 02 0A                         tocol: ..
#
# nb:
# - rhexstr usually contains lowercase chars
# - Works on e.g. versions 1.609.1, 1.625.1 or 2.0
# - Newer versions like e.g. 2.32.1 or 2.487 seems to response with HTTP here but are also still
#   support the older "proprietary" protocol
# - The newer versions are still detected via gb_jenkins_cli_tcp_detect.nasl
if( rhexstr =~ "^556E7265636F676E697A65642070726F746F636F6C3A20020A$" ) {
  service_register( port:port, proto:"jenkins_cli", message:"A Jenkins CLI subsystem service is running at this port." );
  log_message( port:port, data:"A Jenkins CLI subsystem service is running at this port." );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if( ! r0 ) unknown_banner_set( port:port, banner:r );

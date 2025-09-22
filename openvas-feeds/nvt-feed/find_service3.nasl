# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108198");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-07-20 14:08:04 +0200 (Thu, 20 Jul 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with '<xml/>' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It sends a '<xml/>' request to the remaining unknown services and
  tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");

port = get_kb_item( "Services/unknown" );
if( ! port )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

vt_strings = get_vt_strings();

req = "<" + vt_strings["lowercase"] + "/>";
send( socket:soc, data:req + '\r\n' );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to "' + req + '\\r\\n"' );
  exit( 0 );
}

k = "FindService/tcp/" + port + "/xml";
set_kb_item( name:k, value:r );

rhexstr = hexstr( r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:rhexstr );

rbinstr_space = bin2string( ddata:r, noprint_replacement:" " );
rbinstr_nospace = bin2string( ddata:r );

# nb: Zabbix Server is answering with an "OK" here but find_service4.nasl will take the job

if( "oap_response" >< r && "GET_VERSION" >< r ) {
  service_register( port:port, proto:"oap", message:"A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
  log_message( port:port, data:"A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
  exit( 0 );
}

# nb: The GMP service of early GVM-10 versions still answered with an omp_response
# so we only differ between the protocol based on its version detected by
# gb_openvas_manager_detect.nasl.
#
# Examples:
# GOS 3.1 / OpenVAS-8 and probably prior:  <omp_response status="400" status_text="First command must be AUTHENTICATE, COMMANDS or GET_VERSION"/>
# GOS 4.x+ / OpenVAS-9 / GVM-10 and later: <gmp_response status="400" status_text="Only command GET_VERSION is allowed before AUTHENTICATE"/>
if( "GET_VERSION" >< r && ( "omp_response" >< r || "gmp_response" >< r ) ) {
  service_register( port:port, proto:"omp_gmp", message:"A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
  log_message( port:port, data:"A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
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

# 0x00:  4A 44 57 50 2D 48 61 6E 64 73 68 61 6B 65          JDWP-Handshake
# nb: Covered in various find_service*.nasl because the service seems to be unstable and
# we want to try our best to detect this service.
if( r == "JDWP-Handshake" ) {
  service_register( port:port, proto:"jdwp", message:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  log_message( port:port, data:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  exit( 0 );
}

# Port 264/tcp
#
# 0x00:  59 00 00 00                                        Y...
#
# or:
#
# 0x00:  51 00 00 00                                        Q...
#
# nb: See find_service1.nasl and find_service2.nasl as well
if( rhexstr =~ "^5[19]000000$" ) {
  service_register( port:port, proto:"fw1-topology", message:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  log_message( port:port, data:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  exit( 0 );
}

# Juniper Junos OS JUNOScript (3221/tcp)
if( r =~ '^<\\?xml version="1\\.0" encoding="us-ascii"\\?>[^<]+<junoscript xmlns="http://xml\\.juniper\\.net' ) {
  service_register( port:port, proto:"junoscript", message:"Juniper Junos OS JUNOScript seems to be running on this port" );
  replace_kb_item( name:"juniper/junos/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"Juniper Junos OS JUNOScript seems to be running on this port" );
  exit( 0 );
}

# H2 Database
#
# Example for 2.0.204:
# 0x0000:  00 00 00 00 00 00 00 05 00 39 00 30 00 30 00 34    .........9.0.0.4
# 0x0010:  00 37 00 00 00 4B 00 56 00 65 00 72 00 73 00 69    .7...K.V.e.r.s.i
# 0x0020:  00 6F 00 6E 00 20 00 6D 00 69 00 73 00 6D 00 61    .o.n. .m.i.s.m.a
# 0x0030:  00 74 00 63 00 68 00 2C 00 20 00 64 00 72 00 69    .t.c.h.,. .d.r.i
# 0x0040:  00 76 00 65 00 72 00 20 00 76 00 65 00 72 00 73    .v.e.r. .v.e.r.s
# 0x0050:  00 69 00 6F 00 6E 00 20 00 69 00 73 00 20 00 22    .i.o.n. .i.s. ."
# 0x0060:  00 31 00 30 00 31 00 33 00 39 00 33 00 36 00 32    .1.0.1.3.9.3.6.2
# 0x0070:  00 32 00 39 00 22 00 20 00 62 00 75 00 74 00 20    .2.9.". .b.u.t.  # nb: space
# 0x0080:  00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 76    .s.e.r.v.e.r. .v
# 0x0090:  00 65 00 72 00 73 00 69 00 6F 00 6E 00 20 00 69    .e.r.s.i.o.n. .i
# 0x00A0:  00 73 00 20 00 22 00 32 00 30 00 22 FF FF FF FF    .s. .".2.0."....
# 0x00B0:  00 01 5F BF 00 00 01 CB 00 6F 00 72 00 67 00 2E    .._......o.r.g..
# 0x00C0:  00 68 00 32 00 2E 00 6A 00 64 00 62 00 63 00 2E    .h.2...j.d.b.c..
# 0x00D0:  00 4A 00 64 00 62 00 63 00 53 00 51 00 4C 00 4E    .J.d.b.c.S.Q.L.N
# 0x00E0:  00 6F 00 6E 00 54 00 72 00 61 00 6E 00 73 00 69    .o.n.T.r.a.n.s.i
# 0x00F0:  00 65 00 6E 00 74 00 43 00 6F 00 6E 00 6E 00 65    .e.n.t.C.o.n.n.e
# 0x0100:  00 63 00 74 00 69 00 6F 00 6E 00 45 00 78 00 63    .c.t.i.o.n.E.x.c
# 0x0110:  00 65 00 70 00 74 00 69 00 6F 00 6E 00 3A 00 20    .e.p.t.i.o.n.:.  # nb: space
# 0x0120:  00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 20    .V.e.r.s.i.o.n.  # nb: space
# 0x0130:  00 6D 00 69 00 73 00 6D 00 61 00 74 00 63 00 68    .m.i.s.m.a.t.c.h
# 0x0140:  00 2C 00 20 00 64 00 72 00 69 00 76 00 65 00 72    .,. .d.r.i.v.e.r
# 0x0150:  00 20 00 76 00 65 00 72 00 73 00 69 00 6F 00 6E    . .v.e.r.s.i.o.n
# 0x0160:  00 20 00 69 00 73 00 20 00 22 00 31 00 30 00 31    . .i.s. .".1.0.1
# 0x0170:  00 33 00 39 00 33 00 36 00 32 00 32 00 39 00 22    .3.9.3.6.2.2.9."
# 0x0180:  00 20 00 62 00 75 00 74 00 20 00 73 00 65 00 72    . .b.u.t. .s.e.r
# 0x0190:  00 76 00 65 00 72 00 20 00 76 00 65 00 72 00 73    .v.e.r. .v.e.r.s
# 0x01A0:  00 69 00 6F 00 6E 00 20 00 69 00 73 00 20 00 22    .i.o.n. .i.s. ."
# 0x01B0:  00 32 00 30 00 22 00 20 00 5B 00 39 00 30 00 30    .2.0.". .[.9.0.0
# 0x01C0:  00 34 00 37 00 2D 00 32 00 30 00 34 00 5D 00 0A    .4.7.-.2.0.4.]..
# 0x01D0:  00 09 00 61 00 74 00 20 00 6F 00 72 00 67 00 2E    ...a.t. .o.r.g..
# 0x01E0:  00 68 00 32 00 2E 00 6D 00 65 00 73 00 73 00 61    .h.2...m.e.s.s.a
# 0x01F0:  00 67 00 65 00 2E 00 44 00 62 00 45 00 78 00 63    .g.e...D.b.E.x.c
# 0x0200:  00 65 00 70 00 74 00 69 00 6F 00 6E 00 2E 00 67    .e.p.t.i.o.n...g
# 0x0210:  00 65 00 74 00 4A 00 64 00 62 00 63 00 53 00 51    .e.t.J.d.b.c.S.Q
# 0x0220:  00 4C 00 45 00 78 00 63 00 65 00 70 00 74 00 69    .L.E.x.c.e.p.t.i
# 0x0230:  00 6F 00 6E 00 28 00 44 00 62 00 45 00 78 00 63    .o.n.(.D.b.E.x.c
# 0x0240:  00 65 00 70 00 74 00 69 00 6F 00 6E 00 2E 00 6A    .e.p.t.i.o.n...j
# 0x0250:  00 61 00 76 00 61 00 3A 00 36 00 39 00 37 00 29    .a.v.a.:.6.9.7.)
# 0x0260:  00 0A 00 09 00 61 00 74 00 20 00 6F 00 72 00 67    .....a.t. .o.r.g
# 0x0270:  00 2E 00 68 00 32 00 2E 00 6D 00 65 00 73 00 73    ...h.2...m.e.s.s
# 0x0280:  00 61 00 67 00 65 00 2E 00 44 00 62 00 45 00 78    .a.g.e...D.b.E.x
# 0x0290:  00 63 00 65 00 70 00 74 00 69 00 6F 00 6E 00 2E    .c.e.p.t.i.o.n..
# 0x02A0:  00 67 00 65 00 74 00 4A 00 64 00 62 00 63 00 53    .g.e.t.J.d.b.c.S
# 0x02B0:  00 51 00 4C 00 45 00 78 00 63 00 65 00 70 00 74    .Q.L.E.x.c.e.p.t
# 0x02C0:  00 69 00 6F 00 6E 00 28 00 44 00 62 00 45 00 78    .i.o.n.(.D.b.E.x
# 0x02D0:  00 63 00 65 00 70 00 74 00 69 00 6F 00 6E 00 2E    .c.e.p.t.i.o.n..
# 0x02E0:  00 6A 00 61 00 76 00 61 00 3A 00 34 00 39 00 36    .j.a.v.a.:.4.9.6
# 0x02F0:  00 29 00 0A 00 09 00 61 00 74 00 20 00 6F 00 72    .).....a.t. .o.r
# 0x0300:  00 67 00 2E 00 68 00 32 00 2E 00 6D 00 65 00 73    .g...h.2...m.e.s
# 0x0310:  00 73 00 61 00 67 00 65 00 2E 00 44 00 62 00 45    .s.a.g.e...D.b.E
# 0x0320:  00 78 00 63 00 65 00 70 00 74 00 69 00 6F 00 6E    .x.c.e.p.t.i.o.n
# 0x0330:  00 2E 00 67 00 65 00 74 00 28 00 44 00 62 00 45    ...g.e.t.(.D.b.E
# 0x0340:  00 78 00 63 00 65 00 70 00 74 00 69 00 6F 00 6E    .x.c.e.p.t.i.o.n
# 0x0350:  00 2E 00 6A 00 61 00 76 00 61 00 3A 00 32 00 32    ...j.a.v.a.:.2.2
# 0x0360:  00 37 00 29 00 0A 00 09 00 61 00 74 00 20 00 6F    .7.).....a.t. .o
# 0x0370:  00 72 00 67 00 2E 00 68 00 32 00 2E 00 73 00 65    .r.g...h.2...s.e
# 0x0380:  00 72 00 76 00 65 00 72 00 2E 00 54 00 63 00 70    .r.v.e.r...T.c.p
# 0x0390:  00 53 00 65 00 72 00 76 00 65 00 72 00 54 00 68    .S.e.r.v.e.r.T.h
# 0x03A0:  00 72 00 65 00 61 00 64 00 2E 00 72 00 75 00 6E    .r.e.a.d...r.u.n
# 0x03B0:  00 28 00 54 00 63 00 70 00 53 00 65 00 72 00 76    .(.T.c.p.S.e.r.v
# 0x03C0:  00 65 00 72 00 54 00 68 00 72 00 65 00 61 00 64    .e.r.T.h.r.e.a.d
# 0x03D0:  00 2E 00 6A 00 61 00 76 00 61 00 3A 00 31 00 30    ...j.a.v.a.:.1.0
# 0x03E0:  00 37 00 29 00 0A 00 09 00 61 00 74 00 20 00 6A    .7.).....a.t. .j
# 0x03F0:  00 61 00 76 00 61 00 2E 00 62 00 61 00 73 00 65    .a.v.a...b.a.s.e
# 0x0400:  00 2F 00 6A 00 61 00 76 00 61 00 2E 00 6C 00 61    ./.j.a.v.a...l.a
# 0x0410:  00 6E 00 67 00 2E 00 54 00 68 00 72 00 65 00 61    .n.g...T.h.r.e.a
# 0x0420:  00 64 00 2E 00 72 00 75 00 6E 00 28 00 54 00 68    .d...r.u.n.(.T.h
# 0x0430:  00 72 00 65 00 61 00 64 00 2E 00 6A 00 61 00 76    .r.e.a.d...j.a.v
# 0x0440:  00 61 00 3A 00 38 00 32 00 39 00 29 00 0A          .a.:.8.2.9.)..
#
# This ends up in rbinstr_nospace like e.g.:
# 90047KVersion mismatch, driver version is "1013936229" but server version is "20"_org.h2.jdbc.JdbcSQLNonTransientConnectionException: Version mismatch, driver version is "1013936229" but server version is "20" [90047-204]at org.h2.message.DbException.getJdbcSQLException(DbException.java:697)at org.h2.message.DbException.getJdbcSQLException(DbException.java:496)at org.h2.message.DbException.get(DbException.java:227)at org.h2.server.TcpServerThread.run(TcpServerThread.java:107)at java.base/java.lang.Thread.run(Thread.java:829)
#
# nb: See find_service1.nasl as well, the different here is the "driver version" string above in
# the return because our different requests are interpreted as some kind of version.
if( rbinstr_nospace =~ "Version mismatch, driver version is.+but server version is.+org\.h2\.(jdbc|message|server)\." ) {
  service_register( port:port, proto:"h2", message:"A H2 Database service is running at this port." );
  log_message( port:port, data:"A H2 Database service is running at this port." );
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

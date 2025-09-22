# SPDX-FileCopyrightText: 2005 Michel Arboi
# SPDX-FileCopyrightText: New detection methods / pattern / code since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11153");
  script_version("2025-03-14T05:38:04+0000");
  script_tag(name:"last_modification", value:"2025-03-14 05:38:04 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'HELP' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "find_service_3digits.nasl", "rpcinfo.nasl",
                      "dcetest.nasl", "apache_SSL_complain.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It sends a 'HELP' request to the remaining unknown services and
  tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("port_service_func.inc");
include("string_hex_func.inc");
include("dump.inc");
include("misc_func.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

send( socket:soc, data:'HELP\r\n' );
r = recv( socket:soc, length:4096 );
close( soc );

k = "FindService/tcp/" + port + "/get_http";
rget = get_kb_item( k + "Hex" );
if( strlen( rget ) > 0 )
  rget = hex2raw( s:rget );
else
  rget = get_kb_item( k );

if( ! r ) {
  # Mute service
  debug_print( 'service on port ', port, ' does not answer to "HELP"\n' );
  # log_message(port: port, data: "A mute service is running on this port" );
  # jwl TODO:  set kb here and come back and reap the mute services in separate script
  exit( 0 );
}

k = "FindService/tcp/" + port + "/help";
set_kb_item( name:k, value:r );

rhexstr = hexstr( r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:rhexstr );

rbinstr_space = bin2string( ddata:r, noprint_replacement:' ' );
rbinstr_nospace = bin2string( ddata:r );

# The full banner is (without end of line:
# ( success ( 1 2 ( ANONYMOUS ) ( edit-pipeline ) ) )
# ( success ( 2 2 ( ) ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops partial-replay ) ) )
if( r=~ '^\\( success \\( [0-9] [0-9] \\(.*\\) \\(.*' ) {
  service_register( port:port, proto:"subversion" );
  log_message( port:port, data:"A SubVersion server is running on this port" );
  exit( 0 );
}

if( "Invalid protocol verification, illegal ORMI request" >< r ) {
  service_register( port:port, proto:"oracle_application_server" );
  log_message( port:port, data:"An Oracle Application Server is running on this port" );
  exit( 0 );
}

if( raw_string( 0x51, 0x00, 0x00, 0x00 ) >< r && port == 264 ) {
  service_register( port:port, proto:"checkpoint_fw_ng_gettopo_port" );
  log_message( port:port, data:"A CheckPoint FW NG gettopo_port service is running on this port" );
  exit( 0 );
}

# 0x00:  15 03 01 00 02 02 0A
# http://www.hyperic.com/products/open-source-systems-monitoring
# submitted by Brian Clark <bclark@Omeda.com> 15.11.2010
if( raw_string( 0x15,0x03,0x01,0x00,0x02,0x02,0x0a ) >< r && port == 2144 ) {
  service_register( port:port, proto:"hyperic_hq_agent" );
  log_message( port:port, data:"The Hyperic HQ Agent service is running on this port" );
  exit( 0 );
}

#0x00:  FF 00 00 00 00 00 00 00 01 7F                      ..........
if( raw_string( 0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x7F ) >< r ) {
  service_register( port:port, proto:"salt_master" );
  log_message( port:port, data:"Salt Master (http://www.saltstack.com/) is running on this port" );
  exit( 0 );
}

# G-data P2P update distribution (https://public.gdatasoftware.com/Products/Business_v13/EN/Manuals/Business_13_English.pdf)
# 29 01 00 00 06 02 00 00 00 A4 00 00 52 53 41 31  )...........RSA1
# 00 04 00 00 01 00 01 00                          ..........h..3..
# submitted by Landry MINOZA 18.08.2015
if( raw_string( 0x29,0x01,0x00,0x00,0x06,0x02,0x00,0x00,0x00,0xA4,0x00,0x00,0x52,0x53,0x41,0x31,0x00,0x04,0x00,0x00,0x01,0x00,0x01,0x00 ) >< r ) {
  service_register( port:port, proto:"g_data_p2p_update_distribution" );
  log_message( port:port, data:"G-data P2P update distribution is running on this port" );
  exit( 0 );
}

# 0x00:  00 00 00 09 00 00 00 80 00 00 00 00 00 00 00 00    ................
# 0x10:  00 00 04 32 00 00 00 01 00 00 09 5F 00 00 00 68    ...2......._...h
# 0x20:  7A 29 57 2D 38 23 50 52 20 27 2E 57 35 5F 47 6A    z)W-8#PR '.W5_Gj
# 0x30:  7D 25 39 65 37 2E 79 56 6E 67 4D 5E 4F 3E 3B 57    }%9e7.yVngM^O>;W
# 0x40:  78 44 21 3A 32 32 27 7F 61 4A 31 65 59 3F 7A 75    xD!:22'.aJ1eY?zu
# 0x50:  33 38 5D 43 40 30 55 74 7D 62 28 26 48 43 60 6C    38]C@0Ut}b(&HC`l
# 0x60:  51 70 5A 39 74 4A 42 40 47 7F 3F 39 2F 4B 2A 26    QpZ9tJB@G.?9/K*&
# 0x70:  38 5F 25 36 65 20 6A 6A 44 33 61 37 25 78 56 2B    8_%6e jjD3a7%xV+
# 0x80:  2D 54 4A 33 00 00 00 00                            -TJ3....
# http://www.commvault.com/products-backup-recovery.html
# # submitted by Brian Clark <bclark@Omeda.com> 17.11.10

if( raw_string(
0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x04,0x32,0x00,0x00,0x00,0x01,0x00,0x00,0x09,0x5F,0x00,0x00,0x00,0x68,
0x7A,0x29,0x57,0x2D,0x38,0x23,0x50,0x52,0x20,0x27,0x2E,0x57,0x35,0x5F,0x47,0x6A,
0x7D,0x25,0x39,0x65,0x37,0x2E,0x79,0x56,0x6E,0x67,0x4D,0x5E,0x4F,0x3E,0x3B,0x57,
0x78,0x44,0x21,0x3A,0x32,0x32,0x27,0x7F,0x61,0x4A,0x31,0x65,0x59,0x3F,0x7A,0x75,
0x33,0x38,0x5D,0x43,0x40,0x30,0x55,0x74,0x7D,0x62,0x28,0x26,0x48,0x43,0x60,0x6C,
0x51,0x70,0x5A,0x39,0x74,0x4A,0x42,0x40,0x47,0x7F,0x3F,0x39,0x2F,0x4B,0x2A,0x26,
0x38,0x5F,0x25,0x36,0x65,0x20,0x6A,0x6A,0x44,0x33,0x61,0x37,0x25,0x78,0x56,0x2B,
0x2D,0x54,0x4A,0x33,0x00,0x00,0x00,0x00) >< r && port == 8402 ) {
  service_register( port:port, proto:"commvault_client_event_manager" );
  log_message( port:port, data:"The Commvault Client Event Manager service is running on this port" );
  exit( 0 );
}

#0x00:  94 00 00 00 F4 FF FF FF 01 00 00 00 FF FF FF FF    ................
#0x10:  00 00 00 00 A5 00 00 00 00 00 00 00 04 00 00 00    ................
#0x20:  3E F9 E6 B9 9B FE 6B 7C 2D 69 87 74 0B F3 10 66    >.....k|-i.t...f
#0x30:  87 C2 A8 59 A6 18 B4 BD AE BF 7A 5A 3A F4 23 AC    ...Y......zZ:.#.
#0x40:  F6 E4 FC DE 59 80 0C 9F 05 DD BC E5 7E DE 7D 19    ....Y.......~.}.
#0x50:  DC 7D 34 2F EC 2D 63 5D 2F 4E 35 26 DD 7C C3 AB    .}4/.-c]/N5&.|..
#0x60:  AC 13 28 D3 B3 A5 BA F0 FD D6 FA 22 BF 4D F2 4D    ..(........".M.M
#0x70:  A6 70 08 98 0E 7D 82 59 D7 F3 87 3B 9E C7 C5 95    .p...}.Y...;....
#0x80:  06 54 61 43 ED F9 57 BB 50 25 1A B6 A6 61 CE BD    .TaC..W.P%...a..
#0x90:  C1 29 69 76 D5 30 10 CC 60 40 48 EF 8D E0 AC 76    .)iv.0..`@H....v
#0xA0:  FF FE FF FE FF FF FB FF CE BE AC AD FF FF 5B FF    ..............[.
#0xB0:  FF FF FD FF
# # submitted by Matthew Coene <mcoene@Bacardi.com> 26.08.11

if( raw_string(
0x94,0x00,0x00,0x00,0xF4,0xFF,0xFF,0xFF,0x01,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
0x00,0x00,0x00,0x00,0xA5,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,
0x3E,0xF9,0xE6,0xB9,0x9B,0xFE,0x6B,0x7C,0x2D,0x69,0x87,0x74,0x0B,0xF3,0x10,0x66,
0x87,0xC2,0xA8,0x59,0xA6,0x18,0xB4,0xBD,0xAE,0xBF,0x7A,0x5A,0x3A,0xF4,0x23,0xAC,
0xF6,0xE4,0xFC,0xDE,0x59,0x80,0x0C,0x9F,0x05,0xDD,0xBC,0xE5,0x7E,0xDE,0x7D,0x19,
0xDC,0x7D,0x34,0x2F,0xEC,0x2D,0x63,0x5D,0x2F,0x4E,0x35,0x26,0xDD,0x7C,0xC3,0xAB,
0xAC,0x13,0x28,0xD3,0xB3,0xA5,0xBA,0xF0,0xFD,0xD6,0xFA,0x22,0xBF,0x4D,0xF2,0x4D,
0xA6,0x70,0x08,0x98,0x0E,0x7D,0x82,0x59,0xD7,0xF3,0x87,0x3B,0x9E,0xC7,0xC5,0x95,
0x06,0x54,0x61,0x43,0xED,0xF9,0x57,0xBB,0x50,0x25,0x1A,0xB6,0xA6,0x61,0xCE,0xBD,
0xC1,0x29,0x69,0x76,0xD5,0x30,0x10,0xCC,0x60,0x40,0x48,0xEF,0x8D,0xE0,0xAC,0x76,
0xFF,0xFE,0xFF,0xFE,0xFF,0xFF,0xFB,0xFF,0xCE,0xBE,0xAC,0xAD,0xFF,0xFF,0x5B,0xFF,
0xFF,0xFF,0xFD,0xF9 ) >< r && ( port == 2800 || port == 2500 || port == 2501 || port == 2502 || port == 2503 || port == 2506 || port == 2505 || port == 2600 || port == 2801 || port == 2900 ) ) {
  service_register( port:port, proto:"CCure" );
  log_message( port:port, data:"A Ccure security management solution is running on this port" );
  exit( 0 );
}

# [root@f00dikator new_nasl_mods]# telnet 10.10.10.7 7110
# Trying 10.10.10.7...
# Connected to 10.10.10.7.
# Escape character is '^]'.
# hash 30026                              <------- Server
# yo there my brother from another mother <------- Client
# error NOT AUTHORIZED YET                <------- Server
if( "error NOT AUTHORIZED YET" >< r ) {
  service_register( port:port, proto:"DMAIL_Admin" );
  log_message( port:port, data:"The remote host is running a DMAIL Administrative service on this port" );
  exit( 0 );
}

if( "From Server : MESSAGE RECEIVED" >< r ) {
  service_register( port:port, proto:"shixxnote" );
  log_message( port:port, data:"A shixxnote server is running on this port" );
  exit( 0 );
}

# xmlns='jabber:client' xmlns:
# submitted by JYoung ~at- intramedplus.com
if( "xmlns='jabber:client'" >< r ) {
  service_register( port:port, proto:"ejabberd" );
  log_message( port:port, data:"An ejabberd server is running on this port" );
  exit( 0 );
}

if( "Request with malformed data; connection closed" >< r ) {
  service_register( port:port, proto:"moodle-chat-daemom" );
  log_message( port:port, data:"A Moodle Chat Daemon is running on this port" );
  exit( 0 );
}

if( "CONEXANT SYSTEMS, INC." >< r &&
    "ACCESS RUNNER ADSL TERMINAL" >< r ) {
  service_register( port:port, proto:"conexant_telnet" );
  log_message( port:port, data:"A Conexant configuration interface is running on this port" );
  exit( 0 );
}

if (r =~ '^0\\.[67]\\.[0-9] LOG\0 {16}' ) {
  service_register( port:port, proto:"partimage" );
  log_message( port:port, data:"Partimage is running on this port. It requires login." );
  exit( 0 );
}

if( r =~ '^0\\.[67]\\.[0-9]\0 {16}') {
  service_register( port:port, proto:"partimage" );
  log_message( port:port, data:"Partimage is running on this port. It does not require login." );
  exit( 0 );
}

if( "%x%s%p%nh%u%c%z%Z%t%i%e%g%f%a%C" >< r ) {
  service_register( port:port, proto:"egcd" );
  log_message( port:port, data:"egcd is running on this port" );
  exit( 0 );
}

if( "f6ffff10" >< rhexstr && strlen( r ) < 6 ) {
  service_register( port:port, proto:"BackupExec" );
  log_message( port:port, data:"A BackupExec Agent is running on this port" );
  exit( 0 );
}

if( r == '\x00\x00\x00\x03' ) {
  service_register( port:port, proto:"godm" );
  log_message( port:port, data:"AIX Global ODM (a component from HACMP) is running on this port" );
  exit( 0 );
}

if( 'UNKNOWN COMMAND\n' >< r ) {
  service_register( port:port, proto:"clamd" );
  log_message( port:port, data:"A clamd daemon (part of ClamAntivirus) is running on this port" );
  exit( 0 );
}

if( "AdsGone 200" >< r && "HTML Ad" >< r ) {
  service_register( port:port, proto:"adsgone" );
  log_message( port:port, data:"An AdsGone proxy server is running on this port" );
  exit( 0 );
}

if( egrep( pattern:"^Centra AudioServer", string:r ) ) {
  service_register( port:port, proto:"centra" );
  log_message( port:port, data:"A Centra audio server is running on this port" );
  exit( 0 );
}

# TenFour TFS Secure Messaging Server, not RFC compliant
if( 'Ok\r\n500 Command unknown' >< r ) {
  service_register( port:port, proto:"smtp" );
  log_message( port:port, data:"An SMTP server is running on this port" );
  exit( 0 );
}

if( "VERIFY = F$VERIFY" >< r || # Multinet 4.4 Imap daemon...
    "* OK dovecot ready." >< r ) {
  service_register( port:port, proto:"imap" );
  log_message( port:port, data:"An IMAP server is running on this port" );
  exit( 0 );
}

if( "421 Server is temporarily unavailable - pleast try again later" >< r &&
    "421 Service closing control connection" >< r ) {
  service_register( port:port, proto:"ftp-disabled" );
  log_message( port:port, data:"A (disabled) FTP server is running on this port" );
  exit( 0 );
}

if( egrep( pattern:"RTSP/1\.0 505( Protocol | RTSP | )Version [nN]ot [sS]upported", string:r ) ) {
  service_register( port:port, proto:"rtsp" );
  log_message( port:port, data:"A RTSP (shoutcast) server is running on this port" );
  exit( 0 );
}

if( "ERR INVALID-ARGUMENT" >< r &&
    "ERR UNKNOWN-COMMAND" >< r ) {
  service_register( port:port, proto:"nut" );
  log_message( port:port, data:"A Network UPS Tool (NUT) server is running on this port" );
  exit( 0 );
}

if( '\x80\x3d\x01\x03\x01' >< r ) {
  # http://osiris.shmoo.com/
  service_register( port:port, proto:"osiris" );
  log_message( port:port, data:"An Osiris daemon is running on this port" );
  exit( 0 );
}

if( '\x15\x03\x01' == r ) {
  service_register( port:port, proto:"APC_PowerChuteBusinessEdition" );
  log_message( port:port, data:"APC Power Chute Business Edition is running on this port" );
  exit( 0 );
}

if( 'CAP PH\r\n' >< r ) {
  service_register( port:port, proto:"BrightMail_AntiSpam" );
  log_message( port:port, data:"BrightMail AntiSpam is running on this port" );
  exit( 0 );
}

if( '\xea\xdd\xbe\xef' >< r ) {
  service_register( port:port, proto:"veritas-netbackup-client" );
  log_message( port:port, data:"Veritas NetBackup Client Service is running on this port" );
  exit( 0 );
}

# http://www.cisco.com/en/US/products/sw/voicesw/ps556/products_tech_note09186a00801a62b9.shtml#topic1
if( '\x70\x5f\x0a\x10\x01' >< r ) {
  service_register( port:port, proto:"cisco-ris-data-collector" );
  log_message( port:port, data:"A CISCO RIS Data Collector is running on this port" );
  exit( 0 );
}

if( "hello, this is quagga" >< tolower( r ) ) {
  service_register( port:port, proto:"quagga" );
  log_message( port:port, data:"The quagga daemon is listening on this port" );
  exit( 0 );
}

if( 'Hello\n' >< r ) {
  service_register( port:port, proto:"musicdaemon" );
  log_message( port:port, data:"musicdaemon is listening on this port" );
  exit( 0 );
}

if( egrep( pattern:"^220.*Administrator Service ready\.", string:r ) ||
    egrep( pattern:"^220.*eSafe@.*Service ready", string:r ) ) {
  service_register( port:port, proto:"smtp" );
  exit( 0 );
}

# 0x00:  0D 0A 49 6E 74 65 67 72 61 74 65 64 20 70 6F 72    ..Integrated por
# 0x10:  74 0D 0A 50 72 69 6E 74 65 72 20 54 79 70 65 3A    t..Printer Type:
# 0x20:  20 4C 65 78 6D 61 72 6B 20 4D 53 38 31 30 0D 0A     Lexmark MS810..
# 0x30:  50 72 69 6E 74 20 4A 6F 62 20 53 74 61 74 75 73    Print Job Status
# 0x40:  3A 20 4E 6F 20 4A 6F 62 20 43 75 72 72 65 6E 74    : No Job Current
# 0x50:  6C 79 20 41 63 74 69 76 65 0D 0A 50 72 69 6E 74    ly Active..Print
# 0x60:  65 72 20 53 74 61 74 75 73 3A 20 30 20 52 65 61    er Status: 0 Rea
# 0x70:  64 79 0D 0A                                        dy..
#
# nb: This is a "fake" finger server, showing the printer status.
# See find_service1.nasl as well
if( "Integrated port" >< r && "Printer Type" >< r && "Print Job Status" >< r ) {
  service_register( port:port, proto:"fingerd-printer", message:"A printer related finger service seems to be running on this port." );
  log_message( port:port, data:"A printer related finger service seems to be running on this port." );
  set_kb_item( name:"fingerd-printer/" + port + "/banner", value:ereg_replace( string:r, pattern:'(^\r\n|\r\n$)', replace:"" ) );
  exit( 0 );
}

if( "Invalid password!!!" >< r || "Incorrect password!!!" >< r ) {
  service_register( port:port, proto:"wollf" );
  log_message( port:port, data:"A Wollf backdoor is running on this port" );
  exit( 0 );
}

if( "version report" >< r ) {
  service_register( port:port, proto:"gnocatan" );
  log_message( port:port, data:"A gnocatan game server is running on this port" );
  exit( 0 );
}

if( "Welcome on mldonkey command-line" >< r ) {
  service_register( port:port, proto:"mldonkey-telnet" );
  log_message( port:port, data:"A MLdonkey telnet interface is running on this port" );
  exit( 0 );
}

if( egrep(pattern:"^connected\. .*, version:", string:r ) ) {
  service_register( port:port, proto:"subseven" );
  log_message( port:port, data:"A subseven backdoor is running on this port" );
  exit( 0 );
}

if( egrep(pattern:"^220 Bot Server", string:r ) || '\xb0\x3e\xc3\x77\x4d\x5a\x90' >< r ) {
  service_register( port:port, proto:"agobot.fo" );
  log_message( port:port, data:"An Agobot.fo backdoor is running on this port" );
  exit( 0 );
}

if( "RemoteNC Control Password:" >< r ) {
  service_register( port:port, proto:"RemoteNC" );
  log_message( port:port, data:"A RemoteNC console is running on this port" );
  exit( 0 );
}

if( "Sensor Console Password:" >< r ) {
  service_register( port:port, proto:"fluxay" );
  log_message( port:port, data:"A fluxay sensor is running on this port" );
  exit( 0 );
}

if( '\x3c\x65\x72\x72\x6f\x72\x3e\x0a' >< r ) {
  service_register( port:port, proto:"gkrellmd" );
  log_message( port:port, data:"A gkrellmd system monitor daemon is running on this port" );
  exit( 0 );
}

# QMTP / QMQP
if( r =~ '^[1-9][0-9]*:[KZD]' ) {
  service_register( port:port, proto:"QMTP" );
  log_message( port:port, data:"A QMTP / QMQP server is running on this port" );
  exit( 0 );
}

# BZFlag Server (a game on SGI)
if( r =~ '^BZFS' ) {
  service_register( port:port, proto:"bzfs" );
  log_message( port:port, data:"A BZFlag game server seems to be running on this port" );
  exit( 0 );
}

# SGUIL (Snort Monitoring Console)
if( ( "SGUIL" >< r ) && ereg( pattern:"^SGUIL-[0-9]+\.[0-9]+\.[0-9]+ OPENSSL (ENABLED|DISABLED)", string:r ) ) {
  service_register( port:port, proto:"sguil" );
  log_message( port:port, data:"A SGUIL server (Snort Monitoring Console) seems to be running on this port" );
  exit( 0 );
}

# (Solaris) lpd server
if( ereg( pattern: "^Invalid protocol request.*:HHELP.*", string:r ) ) {
  service_register( port:port, proto:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
}

if( strlen( r ) == 4 && '\x3d\x15\x1a\x3d' >< r ) {
  service_register( port:port, proto:"hacker_defender" );
  log_message( port:port, data:"An 'Hacker Defender' backdoor seems to be running on this port" );
  exit( 0 );
}

# http://hea-www.harvard.edu/RD/ds9/
if( "XPA$ERROR unknown xpans request:" >< r ) {
  service_register( port:port, proto:"DS9" );
  log_message( port:port, data:'A DS9 service seems to be running on this port\nSee also : http://hea-www.harvard.edu/RD/ds9/');
  exit( 0 );
}

if( '421 Unauthorized connection to server\n' >< r ) {
  service_register( port:port, proto:"ncic" );
  log_message( port:port, data:"A NCIC service seems to be running on this port" );
  exit( 0 );
}

if( strlen( r ) == 4 && '\x09\x50\x09\x50' >< r ) {
  service_register( port:port, proto:"dell_management_client" );
  log_message( port:port, data:"A Dell Management client seems to be running on this port" );
  exit( 0 );
}

if( "gdm already running. Aborting!" >< r ) {
  service_register( port:port, proto:"xdmcp" );
  log_message( port:port, data:"An xdmcp server seems to be running on this port" );
  exit( 0 );
}

if( strlen( r ) == strlen( "20040616105304" ) &&
    ereg( pattern:"200[0-9][01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]$", string:r ) ) {
  service_register( port:port, proto:"LPTOne" );
  log_message( port:port, data:"A LPTOne server seems to be running on this port" );
  exit( 0 );
}

if( 'ERROR Not authenticated\n' >< r ) {
  service_register( port:port, proto:"hpjfpmd" );
  log_message( port:port, data:"An HP WebJetAdmin server seems to be running on this port" );
  exit( 0 );
}

if( "500 P-Error" >< r && "220 Hello" >< r ) {
  service_register( port:port, proto:"unknown_irc_bot" );
  log_message( port:port, data:"An IRC bot seems to be running on this port" );
  exit( 0 );
}

if( "220 WinSock" >< r ) {
  service_register( port:port, proto:"winsock" );
  log_message( port:port, data:"A WinSock server seems to be running on this port" );
  exit( 0 );
}

if( "DeltaUPS:" >< r ) {
  service_register( port:port, proto:"delta-ups" );
  log_message( port:port, data:"A DeltaUPS monitoring server seems to be running on this port" );
  exit( 0 );
}

if( ereg( pattern:"lpd: .*", string:r ) ) {
  service_register( port:port, proto:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
}

if( ereg( pattern:"^/usr/sbin/lpd.*", string:r ) ) {
  service_register( port:port, proto:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
}

if( "<!doctype html" >< tolower( r ) ) {
  service_register( port:port, proto:"www" );
  log_message( port:port, data:"A (non-RFC compliant) web server seems to be running on this port" );
  exit( 0 );
}

if( "An lpd test connection was completed" >< r || "Bad from address." >< r ||
    "your host does not have line printer access" >< r || "does not have access to remote printer" >< r ) {
  service_register( port:port, proto:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
}

# PPR
if( r =~ "^lprsrv: unrecognized command:" ) {
  service_register( port:port, proto:"lpd", message:"PPR seems to be running on this port." );
  log_message( port:port, data:"PPR seems to be running on this port." );
  exit( 0 );
}

if( ereg( pattern:"^login: Password: (Login incorrect\.)?$", string:r ) ||
    ereg( pattern:"^login: Login incorrect\.", string:r ) ) {
  service_register( port:port, proto:"uucp" );
  log_message( port:port, data:"An UUCP daemon seems to be running on this port" );
  exit( 0 );
}

if( ereg( pattern:"^login: Login incorrect\.$", string:r ) ) {
  service_register( port:port, proto:"uucp" );
  log_message( port:port, data:"An UUCP daemon seems to be running on this port" );
  exit( 0 );
}

# IRC server
if( ereg( pattern:"^:.* 451 .*:", string:r ) ) {
  service_register( port:port, proto:"irc" );
  log_message( port:port, data:"An IRC server seems to be running on this port" );
  exit( 0 );
}

# matterircd IRC server
# https://github.com/42wim/matterircd
if( ereg( pattern:"^:matterircd 461 HELP", string:r ) ) {
  set_kb_item( name:"matterircd/detected", value:TRUE );
  service_register( port:port, proto:"irc" );
  log_message( port:port, data:"An IRC (matterircd) server seems to be running on this port" );
  exit( 0 );
}

# nb: Keep in sync with the second part in find_service1.nasl.
# Daytime seems to be responding late or even not to the HELP
# request here.
if( ereg( pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$",
          string:r ) ||
    ereg( pattern:"^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string:r, icase:TRUE ) ||
    r =~ '^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$' ||
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$' ||
    ereg( pattern:"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string:r ) ||
    # MS flavor of daytime
    ereg(pattern:"^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string:r ) ||
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0?[1-9]|[12][0-9]|3[01])/(0?[1-9]|1[0-2]|3[01])/(19|20)[0-9][0-9][ \t\r\n]*$' ||
    # e.g. 0:00:42 07.02.2018 or 14:07:03 16.01.2018
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[0-2])\\.(19|20)[0-9][0-9][ \t\r\n]*$' ) {
  service_register( port:port, proto:"daytime" );
  log_message( port:port, data:"Daytime is running on this port" );
  exit( 0 );
}

# Banner:
# HP OpenView OmniBack II A.03.10:INET, internal build 325, built on Mon Aug 23 15:50:58 1999.
if( match( string:r, pattern:"HP OpenView OmniBack II*" ) ) {
  service_register( port:port, proto:"omniback" );
  log_message( port:port, data:"HP Omniback seems to be running on this port" );
  exit( 0 );
}

# HP Data Protector A.06.10: INET, internal build 611, built on 2008
# HPE Data Protector A.09.09: INET, internal build 114, built on Tuesday, March 28, 2017, 5:02 PM
# HPE Data Protector A.09.09: INET, internal build 115, built on Dienstag, 23. Mai 2017, 22:16
# HP OpenView Storage Data Protector A.06.00: INET, internal build 331
# HP OpenView Storage Data Protector A.05.50: INET, internal build 330
# HP OpenView Storage Data Protector A.05.00: INET, internal build 190, built on Tue Jul 16 17:37:32 2002.
# Micro Focus Data Protector A.10.03: INET, internal build 181, built on Sunday, March 25, 2018, 6:32 PM
#
# Some services (at least HP Data Protector ones) seems to include NUL chars in their responses as
# seen on:
# https://forum.greenbone.net/t/service-running-on-5555-is-data-protector/15690
# so we need handle this a little bit differentely here...
#
# Method: get_httpHex
# 0x00: 48 00 50 00 20 00 44 00 61 00 74 00 61 00 20 00 H.P. .D.a.t.a. .
# 0x10: 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 6F 00 P.r.o.t.e.c.t.o.
# 0x20: 72 00 20 00 41 00 2E 00 30 00 39 00 2E 00 30 00 r. .A...0...9.0.
# 0x30: 30 00 3A 00 20 00 49 00 4E 00 45 00 54 00 2C 00 0.:. .I.N.E.T.,.
# 0x40: 20 00 69 00 6E 00 74 00 65 00 72 00 6E 00 61 00 .i.n.t.e.r.n.a.
# 0x50: 6C 00 20 00 62 00 75 00 69 00 6C 00 64 00 20 00 l. .b.u.i.l.d. .
# 0x60: 31 00 30 00 31 00 2C 00 20 00 62 00 75 00 69 00 1.0.1.,. .b.u.i.
# 0x70: 6C 00 74 00 20 00 6F 00 6E 00 20 00 32 00 37 00 l.t. .o.n. .2.7.
# 0x80: 20 00 4F 00 63 00 74 00 6F 00 62 00 65 00 72 00 .O.c.t.o.b.e.r.
# 0x90: 20 00 32 00 30 00 31 00 34 00 2C 00 20 00 31 00 .2.0.1.4.,. .1.
# 0xA0: 33 00 3A 00 32 00 34 00 0A 00 00 00             3.:.2.4....
#
# nb: See find_service1.nasl as well and keep the pattern on both the same.
if( r =~ "^(Micro Focus|HPE?) (OpenView Storage )?Data Protector" ||
    rbinstr_nospace =~ "^(Micro Focus|HPE?) (OpenView Storage )?Data Protector" ) {

  service_register( port:port, proto:"hp_dataprotector", message:"Micro Focus/HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );

  if( '\0' >< r )
    replace_kb_item( name:"hp_dataprotector/" + port + "/banner", value:chomp( rbinstr_nospace ) );
  else
    replace_kb_item( name:"hp_dataprotector/" + port + "/banner", value:chomp( r ) );

  log_message( port:port, data:"Micro Focus/HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
  exit( 0 );
}

# Veritas Netbackup
if( r =~ '^1000 +2\n43\nunexpected message received' || "gethostbyaddr: No such file or directory" >< r ) {
  service_register( port:port, proto:"netbackup" );
  log_message( port:port, data:"Veritas Netbackup seems to be running on this port" );
  exit( 0 );
}

# Veritas Backup Exec Remote Agent (6103/tcp)
# or Windows 2000 BackupExec
if( r == '\xf6\xff\xff\xff\x10' ) {
  service_register( port:port, proto:"backup_exec" );
  log_message( port:port, data:"A BackupExec server or Veritas Backup Exec Remote Agent seems to be running on this port" );
  exit( 0 );
}

# Juniper Junos OS JUNOScript (3221/tcp)
if( r =~ '^<\\?xml version="1\\.0" encoding="us-ascii"\\?>[^<]+<junoscript xmlns="http://xml\\.juniper\\.net' ) {
  service_register( port:port, proto:"junoscript" );
  replace_kb_item( name:"juniper/junos/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"Juniper Junos OS JUNOScript seems to be running on this port" );
  exit( 0 );
}

# BMC Patrol
if( r == "SDPACK" ) {
  service_register( port:port, proto:"bmc-perf-sd" );
  log_message( port:port, data:"BMC Perform Service Daemon seems to be running on this port" );
  exit( 0 );
}

# SNPP
if( r =~ '^220 .* SNPP ' || egrep(string: r, pattern: '^214 .*PAGE' ) ) {
  service_register( port:port, proto:"snpp" );
  log_message( port:port, data:"A SNPP server seems to be running on this port" );
  exit( 0 );
}

# HylaFax FTP
if( egrep( string:r, pattern:'^214-? ') && 'MDMFMT' >< r ) {
  service_register( port:port, proto:"hylafax-ftp" );
  log_message( port:port, data:"A HylaFax server seems to be running on this port" );
  exit( 0 );
}

# HylaFAX  (hylafax spp?)
if( egrep( string:r, pattern:"^220.*HylaFAX .*Version.*" ) ) {
  service_register( port:port, proto:"hylafax" );
  log_message( port:port, data:"A HylaFax server seems to be running on this port" );
  exit( 0 );
}

if( egrep( string:r, pattern:"^S: FTGate [0-9]+\.[0-9]+" ) ) {
  service_register( port:port, proto:"ftgate-monitor" );
  log_message( port:port, data:"A FTGate Monitor server seems to be running on this port" );
  exit( 0 );
}

# IRCn
if( strlen( r ) == 2048 && r =~ '^[ ,;:.@$#%+HMX\n-]+$' && '-;;=' >< r &&
    '.;M####+' >< r && '.+ .%########' >< r && ':%.%#########@' >< r ) {
  service_register( port:port, proto:"IRCn-finger" );
  log_message( port:port, data:"IRCn finger service seems to be running on this port" );
  exit( 0 );
}

if( "Melange Chat Server" >< r ) {
  service_register( port:port, proto:"melange-chat" );
  log_message( port:port, data:"Melange Chat Server is running on this port" );
  exit( 0 );
}

# http://www.directupdate.net/
if( r =~ '^OK Welcome .*DirectUpdate server' ) {
  service_register( port:port, proto:"directupdate" );
  log_message( port:port, data:"A DirectUpdate server is running on this port" );
  exit( 0 );
}

# http://www.xboxmediaplayer.de
if( r == "HELLO XBOX!" ) {
  service_register( port:port, proto:"xns" );
  log_message( port:port, data:"A XNS streaming server seems to be running on this port" );
  exit( 0 );
}

# SAP/DB niserver (default port = 7269)
# 0000 4c 00 00 00 03 ff 00 00 ff ff ff ff ff ff ff ff
# 0020 01 00 04 00 4c 00 00 00 00 02 34 00 ff 0d 00 00
# 0040 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
# 0060 00 00 00 00 2e 0f 13 40 00 00 00 00 89 74 09 08
# 0100 05 49 2d 31 00 04 50 ff ff 03 52 01
if( substr( r, 0, 15 ) == hex2raw( s:"4c00000003ff0000ffffffffffffffff" ) ) {
  service_register( port:port, proto:"sap_db_niserver" );
  log_message( port:port, data:"SAP/DB niserver seems to be running on this port" );
  exit( 0 );
}

# Submitted by Lyal Collins
# 00: 01 09 d0 02 ff ff 01 03 12 4c .. . ...L
# DB2 V6 and possibly Db2 V7, running on zOS - TCP ports 446 and 448
if( r == '\x01\x09\xD0\x02\xFF\xFF\x01\x03\x12\x4C' ) {
  service_register( port:port, proto:"db2" );
  log_message( port:port, data:"DB2 is running on this port" );
  exit( 0 );
}

# 00: 43 68 65 63 6b 20 50 6f 69 6e 74 20 46 69 72 65 Check Point Fire
# 10: 57 61 6c 6c 2d 31 20 43 6c 69 65 6e 74 20 41 75 Wall-1 Client Au
# 20: 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 53 65 72 thentication Ser
# 30: 76 65 72 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 67 ver running on g
# 40: 61 74 65 6b 65 65 70 65 72 30 31 2e 6b 61 69 73 atekeeper01.kais
# 50: 65 72 6b 72 61 66 74 2e 64 65 0d 0a 0d ff fb 01 erkraft.de... .
# 60: ff fe 01 ff fb 03 55 73 65 72 3a 20 47 45 54 20 . .User: GET
# 70: 2f 20 48 54 54 50 2f 31 2e 30 0d 0a 55 73 65 72 / HTTP/1.0..User
# 80: 20 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 30 20 GET / HTTP/1.0
# 90: 6e 6f 74 20 66 6f 75 6e 64 0d 0a 0d 0d 0a 55 73 not found.....Us
# a0: 65 72 3a 20                                     er:
if( "Check Point FireWall-1 Client Authentication Server" >< r ) {
  service_register( port:port, proto:"fw1_client_auth" );
  log_message( port:port, data:"Checkpoint Firewall-1 Client Authentication Server seems to be running on this port" );
  exit( 0 );
}

if( r =~ "^200 .* (PWD Server|poppassd)" ) {
  service_register( port:port, proto:"pop3pw" );
  log_message( port:port, data:"A poppassd server seems to be running on this port" );
  exit( 0 );
}

# Ebola antivirus
if( "Welcome to Ebola " >< r ) {
  service_register( port:port, proto:"ebola" );
  set_kb_item( name:"ebola/banner/" + port, value:r );
  log_message( port:port, data:"An Ebola server is running on this port :\n" + r );
  exit( 0 );
}

# www.midas.org
if( r =~ '^MIDASd v[2-9.]+[a-z]? connection accepted' ) {
  service_register( port:port, proto:"midas" );
  log_message( port:port, data:"A MIDAS server is running on this port" );
  exit( 0 );
}

# Crystal Reports
# 00: 73 65 72 76 65 72 20 31 32 38 2e 31 32 38 2e 32 server 128.128.2
# 10: 2e 31 39 37 20 33 2e 35 33 2e 31 61 20 63 6f 6e .197 3.53.1a con
# 20: 6e 65 63 74 69 6f 6e 73 3a 20 32 0a             nections: 2.
if( r =~ '^server [0-9.]+ connections: [0-9]+' ||
    r =~ '^server [0-9.]+ [0-9a-z.]+ connections: [0-9]+' ) {
  service_register( port:port, proto:"crystal" );
  log_message( port:port, data:"Crystal Reports seems to be running on this port" );
  exit( 0 );
}

# Trueweather taskbar applet
if( r =~ '^TrueWeather\r\n\r\n' ) {
  service_register( port:port, proto:"trueweather" );
  log_message( port:port, data:'TrueWeather taskbar applet is running on this port');
  exit( 0 );
}

# W32.IRCBot.E or W32.IRCBot.F or W32.Randex or W32.Korgo.V
if( r == '220 \r\n331 \r\n230 \r\n' ) {
  service_register( port:port, proto:"ircbot" );
  log_message( port:port, data:"A W32.IRCBot backdoor is running on this port" );
  exit( 0 );
}

if( ereg( string:r, pattern:"^RTSP/1\.0 " ) ) {
  service_register( port:port, proto:"rtsp" );
  log_message( port:port, data:"A streaming server is running on this port" );
  exit( 0 );
}

# BMC's ECS product (part of Control-M) gateway listener
# 00: 61 20 30 30 30 30 30 30 32 64 47 52 30 39 33 32    a 0000002dGR0932
# 10: 30 30 30 30 39 30 43 47 47 41 54 45 57 41 59 20    000090CGGATEWAY
# 20: 30 43 47 55 31 30 30 33 31 30 30 36 30 43 47 5f    0CGU100310060CG_
# 30: 41 20 32 32 31 47 41                               A 221GA
if( r =~ '^a [0-9a-zA-Z]+GATEWAY [0-9A-Z]+_A [0-9A-Z]+' ) {
  service_register( port:port, proto:"ctrlm-ecs-gateway" );
  log_message( port:port, data:"An ECS gateway listener (par of Control-M) is running on this port" );
  exit( 0 );
}

# Running on 400/tcp?!
if( r == '\xDE\xAD\xF0\x0D' ) {
  service_register( port:port, proto:"jwalk" );
  log_message( port:port, data:"A Seagull JWalk server is running on this port" );
  exit( 0 );
}

# Contributed by Thomas Reinke - running on TCP/23
# Interface to ADSL router smc7204BRB
if( "CONEXANT SYSTEMS, INC" >< r && "ACCESS RUNNER ADSL CONSOLE PORT" >< r && "LOGON PASSWORD" >< r ) {
  service_register( port:port, proto:"conexant-admin" );
  log_message( port:port, data:"Interface of a Conexant ADSL router is running on this port" );
  exit( 0 );
}

# Default port = 9090
if( r == 'GET %2F HTTP%2F1.0\n' ) {
  service_register( port:port, proto:"slimserver" );
  log_message( port:port, data:"The Slimserver streaming server (command interface) is running on this port" );
  exit( 0 );
}

# 00: 0d 0a 50 72 65 73 73 20 72 65 74 75 72 6e 3a 2a    ..Press return:*
# 10: 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a    ****************
# 20: 0d 0a 45 6e 74 65 72 20 50 61 73 73 77 6f 72 64    ..Enter Password
# 30: 3a 2a 0d 0a 45 6e 74 65 72 20 50 61 73 73 77 6f    :*..Enter Passwo
#  40: 72 64 3a
if( 'Press return:*****************' >< r && 'Enter Password:' >< r ) {
  service_register( port:port, proto:"darkshadow-trojan" );
  set_kb_item( name:"possible-trojan/tcp/" + port + "/name", value:"darkshadow-trojan" );
  set_kb_item( name:"possible-trojan/tcp/detected", value:TRUE );
  set_kb_item( name:"possible-trojan/tcp/port", value:port );
  exit( 0 );
}

# Contributed by David C. Shettler
# http://esupport.ca.com/index.html?/public/dto_transportit/infodocs/LI57895.asp
if( r == 'ACK' ) {
  service_register( port:port, proto:"tng-cam" );
  log_message( port:port, data:"CA Messaging (part of Unicenter TNG) is running on this port" );
  exit( 0 );
}

# Contributed by Jan Dreyer - unfortunately, I could not find much data on
# this Trojan horse. It was found running on port 2400
# The banner is:
# +------------------------+
# | DllTrojan by ScriptGod |
# +------------------------+
# |       [27.04.04]       |
# +------------------------+
# enter pass:
if( "+------------------------+" >< r || "DllTrojan by ScriptGod" >< r ) {
  service_register( port:port, proto:"dll-trojan" );
  set_kb_item( name:"possible-trojan/tcp/" + port + "/name", value:"dll-trojan" );
  set_kb_item( name:"possible-trojan/tcp/detected", value:TRUE );
  set_kb_item( name:"possible-trojan/tcp/port", value:port );
  exit( 0 );
}

# Submitted by Paul Weatherhead
if( r == '\x3d\x15\x1a\x3d' ) {
  service_register( port:port, proto:"rcserv-trojan" );
  set_kb_item( name:"possible-trojan/tcp/" + port + "/name", value:"rcserv-trojan" );
  set_kb_item( name:"possible-trojan/tcp/detected", value:TRUE );
  set_kb_item( name:"possible-trojan/tcp/port", value:port );
  exit( 0 );
}

# $ telnet 10.10.1.203 5110
# Trying 10.10.1.203...
# Connected to 10.10.1.203.
# Escape character is '^]'.
# Sifre_Korumasi                                <------- Server
# HELP                                          <------- Client
# Sifre_Hatasi                                  <------- Server
# 000300Dedected burute force atack from your ip adress   <--- alternative response
#
# $ telnet 10.10.1.203 5112 (same for 51100)
# Trying 10.10.1.203...
# Connected to 10.10.1.203.
# Escape character is '^]'.
# 220 Welcom to ProRat Ftp Server               <------- Server
# HELP                                          <------- Client
# 500 'HELP': command not understood.           <------- Server
# 000300Dedected burute force atack from your ip adress   <--- alternative response
if( 'Sifre_Korumasi' >< r || # nb: In Turkish "Sifre Korumasi" means "password-protected" and "Sifre Hatasi" means "invalid password".
    '000300Dedected burute force atack from your ip adress' >< r ||
    ' Welcom to ProRat Ftp Server' >< r ) {
  service_register( port:port, proto:"prorat-trojan" );
  set_kb_item( name:"possible-trojan/tcp/" + port + "/name", value:"prorat-trojan" );
  set_kb_item( name:"possible-trojan/tcp/detected", value:TRUE );
  set_kb_item( name:"possible-trojan/tcp/port", value:port );
  exit( 0 );
}

if( r == 'ERROR\n' ) {
  service_register( port:port, proto:"streaming21" );
  log_message( port:port, data:"A Streaming21 server seems to be running on this port" );
  exit( 0 );
}

# Submitted by Adam Baldwin - Reference http://evilpacket.net
# Identifies Symantec ManHunt or SNS console (qsp proxy)
# 32 bytes of data sent when a connection is made
# 01 01 00 08 1C EE 01 00 00 00 00 00 00 00 00 00
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
if( r == '\x01\x01\x00\x08\x1c\xee\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ) {
  service_register( port:port, proto:"qsp-proxy" );
  log_message( port:port, data:"A Symantec ManHunt / SNS console (QSP Proxy) seems to be running on this port" );
  exit( 0 );
}

# sunRay Server - thanks to kent@unit.liu.se (Kent Engström)
if( "ERR/InvalidCommand" >< r ) {
  service_register( port:port, proto:"sunraySessionMgr" );
  log_message( port:port, data:"sunraySessionMgr server is running on this port" );
  exit( 0 );
}

# Sun Ray authentication daemon (contrib from Glenn M. Brunette, Jr.)
if( match( string:r, pattern:"protocolErrorInf error=Missing\*state=disconnected*" ) ) {
  service_register( port:port, proto:"sunray-utauthd" );
  log_message( port:port, data:"sunray authentication daemon is running on this port" );
  exit( 0 );
}

# Shoutcast
if( r =~ "^ICY 401" ) {
  service_register( port:port, proto:"shoutcast" );
  log_message( port:port, data:"A shoutcast server seems to be running on this port" );
  exit( 0 );
}

# NFR
if( egrep( pattern:"^Getserver 1\.0 - identify yourself", string:r ) ) {
  service_register( port:port, proto:"nfr-admin-gui" );
  log_message( port:port, data:"An NFR Administrative interface is listening on this port" );
  exit( 0 );
}

# remstats.sf.net
if( "ERROR: unknown directive: " >< r ) {
  service_register( port:port, proto:"remstats" );
  log_message( port:port, data:"A remstats service is running on this port" );
  exit( 0 );
}

if( "NCD X Terminal Configuration" >< r ) {
  service_register( port:port, proto:"ncdx_term_config" );
  log_message( port:port, data:"A NCD X Terminal Configuration service is running on this port" );
  exit( 0 );
}

if( "NPC Telnet permit one" >< r ) {
  service_register( port:port, proto:"telnet" );
  log_message( port:port, data:"A (NPC) telnet service is running on this port" );
  exit( 0 );
}

if( "SiteManager Proxy" >< r ) {
  service_register( port:port, proto:"site_manager_proxy" );
  log_message( port:port, data:"A Site Manager Proxy service is running on this port" );
  exit( 0 );
}

if( egrep( pattern:"^GPSD,.*", string:r ) ) {
  service_register( port:port, proto:"gpsd" );
  log_message( port:port, data:"A gpsd daemon is running on this port" );
  exit( 0 );
}

if( egrep( pattern:"^200.*Citadel(/UX| server ready).*", string:r ) ) {
  service_register( port:port, proto:"citadel/ux" );
  log_message( port:port, data:"A Citadel/UX BBS is running on this port" );
  exit( 0 );
}

if( "Gnome Batalla" >< r ) {
  service_register( port:port, proto:"gnome_batalla" );
  log_message( port:port, data:"A Gnome Batalla service is running on this port" );
  exit( 0 );
}

if( "System Status" >< r && "Uptime" >< r ) {
  service_register( port:port, proto:"systat" );
  log_message( port:port, data:"The systat service is running on this port" );
  exit( 0 );
}

if( "ESTABLISHED" >< r && "TCP" >< r ) {
  service_register( port:port, proto:"netstat" );
  log_message( port:port, data:"The netstat service is running on this port" );
  exit( 0 );
}

# nb: It is expected to have the first authors with a leading space and without the round bracket
# See also gb_qotd_detect_tcp.nasl, gb_qotd_detect_udp.nasl and find_service_spontaneous.nasl
if( r =~ " (A\. A\. Milne|Albert Einstein|Anonimo|Antico proverbio cinese|Autor desconocido|Charles Dickens|Francisco de Quevedo y Villegas|George Bernard Shaw|Jaime Balmes|Johann Wolfgang von Goethe|Jil Sander|Juana de Asbaje|Konfucius|Lord Philip Chesterfield|Montaigne|Petrarca|Ralph Waldo Emerson|Seneca|Syrus|Werner von Siemens)" ||
    r =~ "\((Albert Einstein|Anatole France|August von Kotzebue|Berthold Brecht|Bertrand Russell|Federico Fellini|Fritz Muliar|Helen Markel|Mark Twain|Oscar Wilde|Tschechisches Sprichwort|Schweizer Sprichwort|Volksweisheit)\)" ||
    "(Juliette Gr" >< r || "Dante (Inferno)" >< r || "Semel in anno licet insanire." >< r || "Oh the nerves, the nerves; the mysteries of this machine called man" >< r ||
    "Metastasio (Ipermestra)" >< r || '"\r\nAnonimo' >< r || r =~ '^"[^"]+" *Autor desconocido[ \t\r\n]*$' ) {
  replace_kb_item( name:"qotd/tcp/" + port + "/banner", value:chomp( r ) );
  service_register( port:port, proto:"qotd" );
  log_message( port:port, data:"A qotd (Quote of the Day) service seems to be running on this port." );
  exit( 0 );
}

if( "/usr/games/fortune: not found" >< r ) {
  replace_kb_item( name:"qotd/tcp/" + port + "/banner", value:chomp( r ) );
  service_register( port:port, proto:"qotd" );
  log_message( port:port, data:"A qotd (Quote of the Day) service seems to be running on this port (misconfigured)." );
  exit( 0 );
}

if( "Can't locate loadable object for module" >< r && "BEGIN failed--compilation aborted" >< r ) {
  service_register( port:port, proto:"broken-perl-script" );
  log_message( port:port, data:"A broken perl script is running on this port" );
  exit( 0 );
}

if( "Check Point FireWall-1 authenticated Telnet server" >< r ) {
  service_register( port:port, proto:"fw1-telnet-auth" );
  log_message( port:port, data:"A Firewall-1 authenticated telnet server is running on this port" );
  exit( 0 );
}

if( "NOTICE AUTH : Bitlbee" >< r || "NOTICE AUTH :BitlBee-IRCd initialized" >< r ) {
  service_register( port:port, proto:"irc" );
  log_message( port:port, data:"An IRC server seems to be running on this port" );
  exit( 0 );
}

if( r =~ "^ERROR :Closing Link:.*Throttled: Reconnecting too fast" ||
    r =~ "^:.*NOTICE (Auth|AUTH).*Looking up your hostname" ) {
  service_register( port:port, proto:"irc" );
  log_message( port:port, data:"An IRC server seems to be running on this port" );
  exit( 0 );
}

# 00: 45 52 52 4f 52 3a 20 59 6f 75 72 20 68 6f 73 74 ERROR: Your host
# 10: 20 69 73 20 74 72 79 69 6e 67 20 74 6f 20 28 72 is trying to (r
# 20: 65 29 63 6f 6e 6e 65 63 74 20 74 6f 6f 20 66 61 e)connect too fa
# 30: 73 74 20 2d 2d 20 74 68 72 6f 74 74 6c 65 64 0d st -- throttled.
# 40: 0a .
# Suspicious test?
if( r == 'ERROR: Your host is trying to (re)connect too fast -- throttled\n' ||
    r == 'ERROR :Trying to reconnect too fast.\n' ) {
  service_register( port:port, proto:"irc" );
  log_message( port:port, data:"An IRC server might be running on this port" );
  exit( 0 );
}

if( r =~ '^sh-[0-9.]+# ' ) {
  service_register( port:port, proto:"wild_shell" );
  set_kb_item( name:"possible/backdoor", value:port );
  set_kb_item( name:"backdoor/name", value:"wild_shell" );
  exit( 0 );
}

if( ( "Microsoft Windows [Version " >< r ) &&
     ("(C) Copyright 1985-" >< r ) &&
     ("Microsoft Corp." >< r ) ) {
  service_register( port:port, proto:"wild_shell" );
  set_kb_item( name:"possible/backdoor", value:port );
  set_kb_item( name:"backdoor/name", value:"wild_shell" );
  exit( 0 );
}

if( "1|0|0||" >< r ) {
  service_register( port:port, proto:"PigeonServer" );
  log_message( port:port, data:"PigeonServer seems to be running on this port" );
  exit( 0 );
}

if( r =~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n$' ) {
  service_register( port:port, proto:"kde-lisa" );
  log_message( port:port, data:"KDE Lisa server is running on this port" );
  exit( 0 );
}

# Submitted by Lucian Ravac - See http://zabbix.org
# nb: Seems only an agent is answering to this request, a server will only answer to the request of find_service4.nasl
if( r == 'ZBX_NOTSUPPORTED\n' ||
    ( r =~ '^ZBXD' && 'ZBX_NOTSUPPORTED' >< r ) ) {
  service_register( port:port, proto:"zabbix" );
  log_message( port:port, data:"A Zabbix Agent is running on this port" );
  exit( 0 );
}

# Submitted by Brian Spindel - Gopher on Windows NT
# 00: 33 20 2d 2d 36 20 42 61 64 20 52 65 71 75 65 73    3 --6 Bad Reques
# 10: 74 2e 20 0d 0a 2e 0d 0a                            t.
if( r == '3 --6 Bad request. \r\n.\r\n' ) {
  service_register( port:port, proto:"gopher" );
  log_message( port:port, data:"A Gopher server seems to be running on this port" );
  exit( 0 );
}

# 00: 01 72 6c 6f 67 69 6e 64 3a 20 50 65 72 6d 69 73 .rlogind: Permis
# 10: 73 69 6f 6e 20 64 65 6e 69 65 64 2e 0d 0a sion denied...
if( match( string:r, pattern:'\x01rlogind: Permission denied*', icase:TRUE ) ) {
  service_register( port:port, proto:"rlogin" );
  log_message( port:port, data:"rlogind seems to be running on this port" );
  exit( 0 );
}

# 00: 73 74 61 74 64 20 76 65 72 73 69 6f 6e 3a 33 2e statd version:3.
# 10: 32 20 6d 73 67 69 64 3a 32 30 30 35 2e 30 35 2e 2 msgid:2005.05.
# 20: 31 38 20 31 30 3a 35 30 3a 33 35 0d 0a 18 10:50:35..
# Note: this is *unreliable*, many clones exist
if( match( string:r, pattern:"statd version:*msgid:*" ) ) {
  service_register( port:port, proto:"nagios-statd" );
  log_message( port:port, data:"nagios-statd seems to be running on this port" );
  exit( 0 );
}

# Running on 632/tcp
# 00: 54 68 65 20 73 6d 62 72 69 64 67 65 20 69 73 20 The smbridge is
# 10: 75 73 65 64 20 62 79 20 31 37 32 2e 32 30 2e 34 used by 172.20.4
# 20: 35 2e 31 38 38 0a 0d 54 68 65 20 63 6c 69 65 6e 5.188..The clien
# 30: 74 20 69 73 20 63 6c 6f 73 65 64 21 0a 0d t is closed!..
if( match( string:r, pattern:'The smbridge is used by*' ) ) {
  service_register( port:port, proto:"smbridge" );
  log_message( port:port, data:"IBM OSA SMBridge seems to be running on this port" );
  exit( 0 );
}

# Running on 8649
# 00: 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31    <?xml version="1
# 10: 2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 49 53    .0" encoding="IS
# 20: 4f 2d 38 38 35 39 2d 31 22 20 73 74 61 6e 64 61    O-8859-1" standa
# 30: 6c 6f 6e 65 3d 22 79 65 73 22 3f 3e 0a 3c 21 44    lone="yes"?>.<!D
# 40: 4f 43 54 59 50 45 20 47 41 4e 47 4c 49 41 5f 58    OCTYPE GANGLIA_X
# 50: 4d 4c 20 5b 0a 20 20 20 3c 21 45 4c 45 4d 45 4e    ML [.   <!ELEMEN
# 60: 54 20 47 41 4e 47 4c 49 41 5f 58 4d 4c 20 28 47    T GANGLIA_XML (G
# 70: 52 49 44 29 2a 3e 0a 20 20 20 20 20 20 3c 21 41    RID)*>.      <!A
if( match( string:r, pattern:'<?xml version=*') && " GANGLIA_XML " >< r &&
    "ATTLIST HOST GMOND_STARTED" >< r ) {
  service_register( port:port, proto:"gmond" );
  log_message( port:port, data:"Ganglia monitoring daemon seems to be running on this port" );
  exit( 0 );
}

# Cf. www.nmscommunications.com
if( match( string:r, pattern:'Natural MicroSystem CTAccess Server *' ) ) {
  service_register( port:port, proto:"ctaccess" );
  log_message( port:port, data:"Natural MicroSystem CTAccess Server is running on this port" );
  exit( 0 );
}

# From Jason Johnson
if( r == '\x2f\x44\x94\x72' ) {
  service_register( port:port, proto:"spysweeper" );
  log_message( port:port, data:"Spy Sweeper Enterprise client seems to be running on this port" );
  exit( 0 );
}

# From Justin Fanning
if( r =~ '^\r\nEfficient [0-9]+ DMT Roter .* Ready.*Login:' ) {
  service_register( port:port, proto:"efficient-router" );
  log_message( port:port, data:"An Efficient router administration interface is running on this port" );
  exit( 0 );
}

# From Hartmut Steffin
# HG 1500 Router/Gate (GateKeeper?) built into a siemens HiPath3000
# This is a gate for IP phones.
# 000: 4b 4c 55 47 00 00 00 4a 00 03 00 01 00 00 00 42   KLUG...J.......B
# 010: 02 04 49 50 2d 53 77 41 20 56 30 31 2e 32 38 00   ..IP-SwA V01.28.
# 020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
if( match( string:r, pattern:'KLUG\0*IP-SwA V*\0\0\0\0*' ) ) {
  service_register( port:port, proto:"hg-gate" );
  log_message( port:port, data:"A HG gate for IP phones is running on this port" );
  exit( 0 );
}

# Contrib from Lior Rotkovitch
# 00: 32 32 30 20 41 78 69 73 20 44 65 76 65 6c 6f 70    220 Axis Develop
# 10: 65 72 20 42 6f 61 72 64 20 4c 58 20 72 65 6c 65    er Board LX rele
# 20: 61 73 65 20 32 2e 31 2e 30 20 28 4a 75 6c 20 32    ase 2.1.0 (Jul 2
# 30: 37 20 32 30 30 34 29 20 72 65 61 64 79 2e 0a 35    7 2004) ready..5
# 40: 30 33 20 42 61 64 20 73 65 71 75 65 6e 63 65 20    03 Bad sequence
# 50: 6f 66 20 63 6f 6d 6d 61 6e 64 73 2e 0d 0a          of commands...
if( match( string:r, pattern:'220 Axis Developer Board*ready*503 Bad sequence*' ) ) {
  service_report( port:port, svc:"axis-developer-board" );
  exit( 0 );
}

# From Guenther Konrad
# 00: 68 6f 73 74 73 2f 4b 4c 55 30 31 30 36 65 0a 4b    hosts/KLU0106e.K
# 10: 4c 55 30 31 30 35 65 0a                            LU0105e.
if( substr( r, 0, 5 ) == 'hosts/' ) {
  v = split( substr( r, 6 ), sep:'\n', keep:FALSE );
  if( max_index( v ) == 2 ) {
    service_register( port:port, proto:"ibm-pssp-spseccfg" );
    rep = 'IBM PSSP spseccfg is running on this port.\n';
    if( strlen( v[0] ) > 0 )
      rep = strcat( rep, 'It reports that the DCE hostname is "', v[0], '".\n' );
    else
      rep += 'DCE is not configured on this host\n';
    rep = strcat( rep, 'The system partition name or the local hostname is "', v[1], '".' );
    log_message( port:port, data:rep);
    exit( 0 );
  }
}

if( r == 'ERR password required\r\n' && rget == 'ERR password required\r\nERR password required\r\n' ) {
  service_register( port:port, proto:"fli4l-imonc" );
  log_message( port:port, data:"imonc might be running on this port" );
  exit( 0 );
}

# Does not answer to GET, only to HELP
if( r == '\x06\x00\x00\x00\x00\x00\x1a\x00\x00\x00' ) {
  service_register( port:port, proto:"mldonkey-gui" );
  log_message( port:port, data:"MLDonkey is running on this port (GUI access)" );
  exit( 0 );
}

# If you do not want to "double check", uncomment the next two lines
# if (! r0) unknown_banner_set(port: port, banner: r);
#  exit( 0 );

########################################################################
#                   **** WARNING ****                                  #
# Do not add anything below unless it should handled by find_service   #
# or find_service1 or find_service_3digits                             #
# The exception is qotd -- look at the bottom of the file              #
########################################################################

function report_and_exit( port, data ) {
  log_message( port:port, data:data );
  exit( 0 );
}

########################################################################
# All the following services should already have been identified by    #
# find_service.nasl or find_service1.nasl; anyway, we double check in   #
# case they failed...                                                  #
########################################################################

if( r == 'HELP\r\n\r\n' ) {
  service_register( port:port, proto:"echo" );
  report_and_exit( port:port, data:'Echo "simple TCP/IP service" is running on this port' );
}

# Spamd (port 783) - permissive Regex, just in case
if( r =~ '^SPAMD/[0-9.]+ [0-9]+ Bad header line:' ) {
  service_register( port:port, proto:"spamd" );
  report_and_exit( port:port, data:"A SpamAssassin daemon is running on this port" );
}

# SOCKS5
if( strlen( r ) > 3 && ord( r[0] ) == 5 && ord( r[1] ) <= 8 && ord( r[2] ) == 0 && ord( r[3] ) <= 4 ) {
  service_register( port:port, proto:"socks5" );
  report_and_exit( port:port, data:"A SOCKS5 server seems to be running on this port" );
}

# SOCKS4
if( strlen( r ) > 1 && ord( r[0] ) == 0 && ord( r[1] ) >= 90 && ord( r[1] ) <= 93 ) {
  service_register( port:port, proto:"socks4" );
  report_and_exit( port:port, data:"A SOCKS4 server seems to be running on this port" );
}

if( egrep( pattern:"^\+OK.*POP2.*", string:r, icase:TRUE ) ) {
  service_register( port:port, proto:"pop2" );
  report_and_exit( port:port, data:"A POP2 server seems to be running on this port" );
} else if( egrep( pattern:"^\+OK.*POP.*", string:r, icase:TRUE ) ||
           egrep( pattern:"^\+OK.*Dovecot.*ready.", string:r, icase:TRUE ) ) {
  # nb: Don't set the received banner into the KB as we want to do additional POP3
  # fingerprinting via the CAPA / IMPLEMENTATION banner in pop3_get_banner().
  service_register( port:port, proto:"pop3" );
  report_and_exit( port:port, data:"A POP3 server seems to be running on this port" );
}

# FTP - note that SMTP & SNPP also return 220 & 214 codes
if( egrep( pattern:"^220 .*FTP", string:r, icase:TRUE ) ||
    egrep( pattern:"^214-? .*FTP", string:r, icase:TRUE ) ||
    egrep( pattern:"^220 .*CrownNet", string:r, icase:TRUE ) ||
    ( egrep( pattern:"^220 ", string:r ) && egrep( pattern:"^530 Please login with USER and PASS", string:r, icase:TRUE ) ) ) {
  banner = egrep( pattern:"^2[01][04]-? ", string:r );
  if( banner ) set_kb_item( name:"ftp/banner/" + port, value:banner );
  service_register( port:port, proto:"ftp" );
  report_and_exit( port:port, data:"A FTP server seems to be running on this port" );
}

# SMTP
if( egrep( pattern:"^220( |-).*(SMTP|mail)", string:r, icase:TRUE ) ||
    egrep( pattern:"^214-? .*(HELO|MAIL|RCPT|DATA|VRFY|EXPN)", string:r ) ||
    egrep( pattern:"^220-? .*OpenVMS.*ready", string:r ) ||
    egrep( pattern:"^421-? .*SMTP", string:r ) ) {
  service_register( port:port, proto:"smtp" );
  report_and_exit( port:port, data:"A SMTP server seems to be running on this port" );
}

# NNTP
if( egrep( pattern:"^20[01] .*(NNTP|NNRP)", string:r ) ||
    egrep( pattern:"^100 .*commands", string:r, icase:TRUE ) ) {
  banner = egrep( pattern:"^200 ", string:r );
  if( banner ) set_kb_item( name:"nntp/banner/" + port, value:chomp( banner ) );
  service_register( port:port, proto:"nntp" );
  report_and_exit( port:port, data:"A NNTP server seems to be running on this port" );
}

# SSH
if( egrep( pattern:"^SSH-", string:r ) ) {
  service_register( port:port, proto:"ssh" );
  report_and_exit( port:port, data:"A SSH server seems to be running on this port" );
}

# Contrib from Maarten
# 00: 0d 0a 44 65 73 74 69 6e 61 74 69 6f 6e 20 73 65 ..Destination se
# 10: 72 76 65 72 20 64 6f 65 73 20 6e 6f 74 20 68 61 rver does not ha
# 20: 76 65 20 53 73 68 20 61 63 74 69 76 61 74 65 64 ve Ssh activated
# 30: 2e 0d 0a 43 6f 6e 74 61 63 74 20 43 69 73 63 6f ...Contact Cisco
# 40: 20 53 79 73 74 65 6d 73 2c 20 49 6e 63 20 74 6f Systems, Inc to
# 50: 20 70 75 72 63 68 61 73 65 20 61 0d 0a 6c 69 63 purchase a..lic
# 60: 65 6e 73 65 20 6b 65 79 20 74 6f 20 61 63 74 69 ense key to acti
# 70: 76 61 74 65 20 53 73 68 2e 0d 0a vate Ssh...
if( "Destination server does not have Ssh activated" >< r ) {
  service_register( port:port, proto:"disabled-ssh" );
  report_and_exit( port:port, data:"A disabled SSH service seems to be running on this port" );
}

# Auth
if( egrep( string:r, pattern:"^0 *, *0 *: * ERROR *:" ) ) {
  service_register( port:port, proto:"auth" );
  report_and_exit( port:port, data:"An Auth/ident server seems to be running on this port" );
}

# Finger
if( ( egrep( string:r, pattern:"HELP: no such user", icase:TRUE ) ) ||
    ( egrep( string:r, pattern:".*Line.*User.*Host", icase:TRUE ) ) ||
    ( egrep( string:r, pattern:".*Login.*Name.*TTY", icase:TRUE ) ) ||
    '?Sorry, could not find "GET"' >< r ||
    'Login name: HELP' >< r ||
    ( ( 'Time Since Boot:' >< r ) && ("Name        pid" >< r ) ) ) {
  service_register( port:port, proto:"finger" );
  report_and_exit( port:port, data:"A finger server seems to be running on this port" );
}

# HTTP
if( ( "501 Method Not Implemented" >< r ) || ( ereg( string:r, pattern:"^HTTP/1\.[01]")) || "action requested by the browser" >< r ) {
  service_register( port:port, proto:"www" );
  report_and_exit( port:port, data:"A web server seems to be running on this port" );
}

# BitTorrent - no need to send anything to get the banner, in fact
if( r =~ "^BitTorrent protocol" ) {
  service_register( port:port, proto:"BitTorrent" );
  report_and_exit( port:port, data:"A BitTorrent server seems to be running on this port" );
}

# Jabber C2S and S2S servers return the same error and cannot be identified precisely by this test only.
if( match( string:r, pattern:"<stream:stream xmlns:stream='http://etherx.jabber.org/streams'*</stream:stream>", icase:TRUE ) ||
    # Jabber (http://www.jabber.org) detection (usually on 5222/tcp).
    "<stream:error>Invalid XML</stream:error>" >< r ||
    # Oracle Messenger (Jabber) detection (usually on 5222/tcp,5223/tcp for TLS).
    "<stream:error>Connection is closing</stream:error></stream:stream>" >< r ) {
  service_register( port:port, proto:"jabber" );
  report_and_exit( port:port, data:"A jabber server seems to be running on this port" );
}

# Zebra vty
if( "Hello, this is zebra " >< r ) {
  service_register( port:port, proto:"zebra" );
  set_kb_item( name:"zebra/banner/" + port, value:r );

  cpe = build_cpe( value:r, exp:"^([0-9.]+([a-z])?)", base:"cpe:/a:gnu:zebra:" );
  if( ! isnull( cpe ) )
    register_host_detail( name:"App", value:cpe );

  report_and_exit( port:port, data:"A zebra daemon is running on this port" );
}

# IMAP4
# * OK IMAP (C) example.com (Version 7.3e2-2)
# * OK mailproc (cimap)
# * OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready
# * OK IMAP4 ready
# * OK example.com (cimap)
if( egrep( pattern:"^\* *OK .* IMAP", string:r ) ||
    egrep( pattern:"^\* *OK IMAP", string:r ) ||
    egrep( pattern:"^\* *OK .* cimap", string:r ) ||
    # nb: The following three are from nasl_bultin_find_service.c.
    # The first two pattern are used without a space between * and ok there, we're checking both here.
    egrep( pattern:"^\* ?ok iplanet messaging multiplexor", string:r, icase:TRUE ) ||
    egrep( pattern:"^\* ?ok communigate pro imap server", string:r, icase:TRUE ) ||
    egrep( pattern:"^\* ok courier-imap", string:r, icase:TRUE ) ) {
  service_register( port:port, proto:"imap" );
  report_and_exit( port:port, data:"An IMAP server is running on this port" );
}

if( "cvs [pserver]" >< r ) {
  service_register( port:port, proto:"cvspserver" );
  report_and_exit( port:port, data:"A CVS pserver is running on this port" );
}

# chargen service, this has a longer string (the following is only an excerpt) like e.g.:
#
# 0x0000:  20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F     !"#$%&'()*+,-./
# 0x0010:  30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F    0123456789:;<=>?
# 0x0020:  40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F    @ABCDEFGHIJKLMNO
# 0x0030:  50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F    PQRSTUVWXYZ[\]^_
# 0x0040:  60 61 62 63 64 65 66 67 0D 0A 21 22 23 24 25 26    `abcdefg..!"#$%&
# 0x0050:  27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36    '()*+,-./0123456
# 0x0060:  37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46    789:;<=>?@ABCDEF
# 0x0070:  47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56    GHIJKLMNOPQRSTUV
# 0x0080:  57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66    WXYZ[\]^_`abcdef
# 0x0090:  67 68 0D 0A 22 23 24 25 26 27 28 29 2A 2B 2C 2D    gh.."#$%&'()*+,-
# 0x00A0:  2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D    ./0123456789:;<=
#
# Ensuring that at least 3 patterns match
# In case a pattern is missing or doesn't make it into the response (due to it being slow), the service will still be reported
# nb: See also find_service2.nasl and gb_chargen_detect_tcp.nasl/gb_chargen_detect_udp.nasl
chargen_found = 0;
foreach chargen_pattern( make_list( '!"#$%&\'()*+,-./', "ABCDEFGHIJ", "abcdefg", "0123456789", ":;<=>?@", "KLMNOPQRSTUVWXYZ" ) ) {
  if( chargen_pattern >< r )
    chargen_found++;
}
if( chargen_found > 2 ) {
  replace_kb_item( name:"chargen/tcp/" + port + "/banner", value:chomp( r ) );
  service_register( port:port, proto:"chargen" );
  report_and_exit( port:port, data:"A chargen server is running on this port" );
}

# This is an IRC bouncer!
if( egrep( pattern:":Welcome!.*NOTICE.*psyBNC", icase:TRUE, string:r ) ) {
  service_register( port:port, proto:"psyBNC" );
  report_and_exit( port:port, data:"psyBNC seems to be running on this port" );
}

if( "CCProxy Telnet Service Ready" >< r ) {
  service_register( port:port, proto:"ccproxy-telnet" );
  log_message( port:port, data:"CCProxy (telnet) seems to be running on this port" );
  exit( 0 );
}

if( "CCProxy FTP Service" >< r ) {
  service_register( port:port, proto:"ccproxy-ftp" );
  log_message( port:port, data:"CCProxy (ftp) seems to be running on this port" );
  exit( 0 );
}

if( "CCProxy " >< r  && "SMTP Service Ready" >< r ) {
  service_register( port:port, proto:"ccproxy-smtp" );
  log_message( port:port, data:"CCProxy (smtp) seems to be running on this port" );
  exit( 0 );
}

if( "CMailServer " >< r  && "SMTP Service Ready" >< r ) {
  service_register( port:port, proto:"cmailserver-smtp" );
  log_message( port:port, data:"CMailServer (smtp) seems to be running on this port" );
  exit( 0 );
}

# 0000000 30 11 00 00 00 00 00 00 d7 a3 70 3d 0a d7 0d 40
#          0 021  \0  \0  \0  \0  \0  \0   ×   £   p   =  \n   ×  \r   @
# 0000020 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
#         \0  \0  \0  \0  \0  \0  \0  \0 001  \0  \0  \0 001  \0  \0  \0
# 0000040 00 00 00 00 02 00 00 00
#         \0  \0  \0  \0 002  \0  \0  \0
# 0000050
if( ( r =~ '^\x30\x11\x00\x00\x00\x00\x00\x00' ) && ( strlen( r ) == 40 ) ) {
  service_register( port:port, proto:"dameware" );
  log_message( port:port, data:"Dameware seems to be running on this port" );
  exit( 0 );
}

if( "Cirrato Client" >< r ) {
  service_register( port:port, proto:"cirrato" );
  report_and_exit( port:port, data:"Cirrato Client seems to be running on this port." );
}

if( '501 "Invalid command"' >< r && ereg( pattern:"^[0-9][0-9][0-9].+MailSite Mail Management Server .+ ready", string:r ) ) {
  service_register( port:port, proto:"mailma" );
  report_and_exit( port:port, data:"MailSite's Mail Management Agent (MAILMA) seems to be running on this port." );
}

if( egrep( pattern:"^[0-9][0-9][0-9][0-9]-NMAP \$Revision: .+Help", string:r ) ) {
  service_register( port:port, proto:"novell_nmap" );
  log_message(port: port, data:"A Novell Network Messaging Application Protocol (NMAP) agent seems to be running on this port" );
  exit( 0 );
}

if( "Open DC Hub, version" >< r  && "administrators port" >< r ) {
  service_register( port:port, proto:"opendchub" );
  log_message( port:port, data:"Open DC Hub Administrative interface (peer-to-peer) seems to be running on this port" );
  exit( 0 );
}

if( ereg( pattern:"^$MyNick ", string:r ) ) {
  service_register( port:port, proto:"DirectConnect" );
  log_message( port:port, data:"Direct Connect seems to be running on this port" );
  exit( 0 );
}

if( ereg( pattern:"^RFB [0-9]", string:r ) ) {
  service_register( port:port, proto:"vnc" );
  replace_kb_item(name:"vnc/banner/" + port , value:r );
  log_message( port:port, data:"A VNC server seems to be running on this port" );
  exit( 0 );
}

if( egrep( pattern:"^BZFS00", string:r ) ) {
  service_register( port:port, proto:"bzFlag" );
  log_message( port:port, data:"A bzFlag server seems to be running on this port" );
  exit( 0 );
}

# MS DTC
if( strlen( r ) == 3 && ( r[2] == '\x10' || # same test as find_service
                          r[2] == '\x0b' ) ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' ) {
  service_register( port:port, proto:"msdtc" );
  log_message( port:port, data:"A MSDTC server seems to be running on this port" );
  exit( 0 );
}

if( "Welcome to the TeamSpeak 3 ServerQuery interface" >< r ) {
  service_register( port:port, proto:"teamspeak-serverquery" );
  report_and_exit( port:port, data:"A Teamspeak 3 ServerQuery interface seems to be running on this port." );
}

if( "[TS]" >< r ) {
  service_register( port:port, proto:"teamspeak-tcpquery" );
  report_and_exit( port:port, data:"A Teamspeak 2 Query interface seems to be running on this port." );
}

if( r == 'GIOP\x01' ) {
  service_register( port:port, proto:"giop" );
  log_message( port:port, data:"A GIOP-enabled service is running on this port" );
  exit( 0 );
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
#
# or:
#
# 0x00:  22 49 4D 50 4C 45 4D 45 4E 54 41 54 49 4F 4E 22    "IMPLEMENTATION"
# 0x10:  20 22 41 70 61 63 68 65 20 4D 61 6E 61 67 65 53     "Apache ManageS
# 0x20:  69 65 76 65 20 76 31 2E 30 22 0D 0A 22 53 54 41    ieve v1.0".."STA
# 0x30:  52 54 54 4C 53 22 0D 0A 22 53 49 45 56 45 22 20    RTTLS".."SIEVE"  # nb: space
# 0x40:  22 6C 6F 67 20 66 69 6C 65 69 6E 74 6F 20 72 65    "log fileinto re
# 0x50:  6A 65 63 74 20 76 61 63 61 74 69 6F 6E 20 69 3B    ject vacation i;
# 0x60:  61 73 63 69 69 2D 6E 75 6D 65 72 69 63 20 65 6E    ascii-numeric en
# 0x70:  76 65 6C 6F 70 65 20 62 6F 64 79 22 0D 0A 22 53    velope body".."S
# 0x80:  41 53 4C 22 20 22 50 4C 41 49 4E 22 0D 0A 22 56    ASL" "PLAIN".."V
# 0x90:  45 52 53 49 4F 4E 22 20 22 31 2E 30 22 0D 0A 4E    ERSION" "1.0"..N
# 0xA0:  4F 20 75 6E 6B 6E 6F 77 6E 20 48 45 4C 50 20 63    O unknown HELP c
# 0xB0:  6F 6D 6D 61 6E 64 0D 0A                            ommand..
#
# or:
#
# 0x0000:  22 49 4D 50 4C 45 4D 45 4E 54 41 54 49 4F 4E 22    "IMPLEMENTATION"
# 0x0010:  20 22 44 6F 76 65 63 6F 74 20 50 69 67 65 6F 6E     "Dovecot Pigeon
# 0x0020:  68 6F 6C 65 22 0D 0A 22 53 49 45 56 45 22 20 22    hole".."SIEVE" "
# 0x0030:  66 69 6C 65 69 6E 74 6F 20 72 65 6A 65 63 74 20    fileinto reject  # nb: space
# 0x0040:  65 6E 76 65 6C 6F 70 65 20 65 6E 63 6F 64 65 64    envelope encoded
# 0x0050:  2D 63 68 61 72 61 63 74 65 72 20 76 61 63 61 74    -character vacat
# 0x0060:  69 6F 6E 20 73 75 62 61 64 64 72 65 73 73 20 63    ion subaddress c
# 0x0070:  6F 6D 70 61 72 61 74 6F 72 2D 69 3B 61 73 63 69    omparator-i;asci
# 0x0080:  69 2D 6E 75 6D 65 72 69 63 20 72 65 6C 61 74 69    i-numeric relati
# 0x0090:  6F 6E 61 6C 20 72 65 67 65 78 20 69 6D 61 70 34    onal regex imap4
# 0x00A0:  66 6C 61 67 73 20 63 6F 70 79 20 69 6E 63 6C 75    flags copy inclu
# 0x00B0:  64 65 20 76 61 72 69 61 62 6C 65 73 20 62 6F 64    de variables bod
# 0x00C0:  79 20 65 6E 6F 74 69 66 79 20 65 6E 76 69 72 6F    y enotify enviro
# 0x00D0:  6E 6D 65 6E 74 20 6D 61 69 6C 62 6F 78 20 64 61    nment mailbox da
# 0x00E0:  74 65 20 69 6E 64 65 78 20 69 68 61 76 65 20 64    te index ihave d
# 0x00F0:  75 70 6C 69 63 61 74 65 20 6D 69 6D 65 20 66 6F    uplicate mime fo
# 0x0100:  72 65 76 65 72 79 70 61 72 74 20 65 78 74 72 61    reverypart extra
# 0x0110:  63 74 74 65 78 74 20 69 6D 61 70 66 6C 61 67 73    cttext imapflags
# 0x0120:  20 6E 6F 74 69 66 79 20 69 6D 61 70 73 69 65 76     notify imapsiev
# 0x0130:  65 20 76 6E 64 2E 64 6F 76 65 63 6F 74 2E 69 6D    e vnd.dovecot.im
# 0x0140:  61 70 73 69 65 76 65 22 0D 0A 22 4E 4F 54 49 46    apsieve".."NOTIF
# 0x0150:  59 22 20 22 6D 61 69 6C 74 6F 22 0D 0A 22 53 41    Y" "mailto".."SA
# 0x0160:  53 4C 22 20 22 50 4C 41 49 4E 20 4C 4F 47 49 4E    SL" "PLAIN LOGIN
# 0x0170:  20 44 49 47 45 53 54 2D 4D 44 35 20 43 52 41 4D     DIGEST-MD5 CRAM
# 0x0180:  2D 4D 44 35 22 0D 0A 22 53 54 41 52 54 54 4C 53    -MD5".."STARTTLS
# 0x0190:  22 0D 0A 22 56 45 52 53 49 4F 4E 22 20 22 31 2E    ".."VERSION" "1.
# 0x01A0:  30 22 0D 0A 4F 4B 20 22 44 6F 76 65 63 6F 74 20    0"..OK "Dovecot  # nb: space
# 0x01B0:  72 65 61 64 79 2E 22 0D 0A 4E 4F 20 22 45 72 72    ready."..NO "Err
# 0x01C0:  6F 72 20 69 6E 20 4D 41 4E 41 47 45 53 49 45 56    or in MANAGESIEV
# 0x01D0:  45 20 63 6F 6D 6D 61 6E 64 20 72 65 63 65 69 76    E command receiv
# 0x01E0:  65 64 20 62 79 20 73 65 72 76 65 72 2E 22 0D 0A    ed by server."..
if( egrep( string:r, pattern:'^"IMPLEMENTATION" "[^"]+"', icase:FALSE ) &&
    egrep( string:r, pattern:'^"SIEVE" "[^"]+"', icase:FALSE ) ) {
  service_register( port:port, proto:"sieve" );
  log_message( port:port, data:"A Sieve mail filter daemon seems to be running on this port." );
  exit( 0 );
}

# https://tools.ietf.org/html/rfc2204
# 0x00:  10 00 00 17 49 4F 44 45 54 54 45 20 46 54 50 20    ....IODETTE FTP
# 0x10:  52 45 41 44 59 20 0D                               READY .
if( "IODETTE FTP READY" >< r ) {
  service_register( port:port, proto:"odette-ftp" );
  report_and_exit( port:port, data:"A service providing a ODETTE File Transfer Protocol seems to be running on this port." );
}

# Running on a Hama IR110 WiFi Radio on port 514/tcp
# (Thread0): [      2.185608] I2S    (2): After waiting approx. 0.0 seconds...
# (Thread0): [      2.185860] I2S    (2): Timer fired at 0x00215C2E
# (Thread0): [      2.186123] SPDIF  (2): Timer fired at 0x00215E40
# (Thread2): [     16.463611] NET    (2): Notify Eth Link i/f 1 UP
# (Thread2): [     21.894697] NET    (2): Notify IP i/f 1 (192.168.0.1) UP
# (Thread2): [     22.072539] HTTP   (2): Found existing handle 1 (hama.wifiradiofrontier.com:80)
# (Thread2): [     22.158205] CB     (2): Received interface callback data ok.
# (Thread2): [     23.451059] UI     (2): IntSetupWizard connected
# (Thread0): [     25.139968] I2S    (2): After waiting approx. 0.0 seconds...
# (Thread0): [     25.140278] I2S    (2): Timer fired at 0x017F9D9A
# (Thread0): [     25.140583] SPDIF  (2): Timer fired at 0x017FA01F
# (Thread2): [     49.340946] RSA    (2): fsRsaGenerateKeyTask: Key created. Time taken 49299ms
#
# or:
#
# (Thread0): [  11828.608232] I2S    (2): After waiting approx. 0.0 seconds...
# (Thread0): [  11828.608552] I2S    (2): Timer fired at 0xC10A3F89
# (Thread0): [  11828.608895] SPDIF  (2): Timer fired at 0xC10A4232
#
# or:
#
# (Thread2): [1630977.775666] WFSAPI (2): File not found
#
# or:
#
# (Thread2): [      0.608082] AUDSYN (2): audioSyncInit(serverCapable=1, clientCapable=1)
#
# nb: The same is also checked in find_service1.nasl and find_service_spontaneous.nasl but sometimes
# the requests are coming in late or not coming in at all and these are missing the detection so it
# is also checked here.
#
if( "(Thread" >< r && ( "Notify Wlan Link " >< r ||
    "Notify Eth Link " >< r ||
    "Received unknown command on socket" >< r ||
    "fsfsFlashFileHandleOpen" >< r ||
    "Found existing handle " >< r ||
    "After waiting approx. " >< r ||
    "Timer fired at " >< r ||
    "ControlSocketServerInstructClientToLeave" >< r ||
    ( "AUDSYN" >< r && "audioSyncInit" >< r ) ||
    ( "WFSAPI" >< r && "File not found" >< r ) ) ) {
  service_register( port:port, proto:"wifiradio-setup", message:"A WiFi radio setup service seems to be running on this port." );
  log_message( port:port, data:"A WiFi radio setup service seems to be running on this port." );
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

# nb: The same pattern is also checked in gb_rsync_remote_detect.nasl and find_service1.nasl.
# Please update those when updating the pattern here.
if( r =~ "^@RSYNCD: [0-9.]+" || r =~ "^You are not welcome to use rsync from " || r =~ "^rsync: (link_stat |error |.+unknown option)" ||
    r =~ "rsync error: (syntax or usage error|some files/attrs were not transferred) " || r =~ "rsync\s+version [0-9.]+\s+protocol version [0-9.]+" ) {
  service_register( port:port, proto:"rsync", message:"A service supporting the rsync protocol is running at this port." );
  log_message( port:port, data:"A service supporting the rsync protocol is running at this port." );
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
# nb: See find_service1.nasl and find_service3.nasl as well
if( rhexstr =~ "^5[19]000000$" ) {
  service_register( port:port, proto:"fw1-topology", message:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  log_message( port:port, data:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  exit( 0 );
}

# nb: See find_service_3digits.nasl and other find_service* as well
if( egrep( string:r, pattern:"^220 (HP|JetDirect) GGW server \(version ([0-9.]+)\) ready" ) ) {
  service_register( port:port, proto:"hp-gsg", message:"A Generic Scan Gateway (GGW) server service is running at this port." );
  log_message( port:port, data:"A Generic Scan Gateway (GGW) server service is running at this port." );
  exit( 0 );
}

# Some services are responding with an SSL/TLS alert we currently don't recognize
# e.g. 0x00:  15 03 03 00 02 02 16                               .......
# See also "Alert Protocol format" in http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
if( rhexstr =~ "^15030[0-3]00020[1-2]..$" ||
    rhexstr =~ "^1500000732$" || # nb: e.g. Novell Zenworks prebootserver on 998/tcp
    rhexstr =~ "^150301$" ) {
  service_register( port:port, proto:"ssl", message:"A service responding with an SSL/TLS alert seems to be running on this port." );
  log_message( port:port, data:"A service responding with an SSL/TLS alert seems to be running on this port." );
  exit( 0 );
}

# Seen for/on JetDirect lpd.
# nb: See find_service1.nasl as well. This was just added here as a fallback if the first detection
# / connection has some hiccup.
if( port == 515 && rhexstr =~ "^ff$" ) {
  service_register( port:port, proto:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
}

# Seen on e.g. port:
# - 9650/tcp (on OpenSearch docker containers)
# - 4690/tcp (on Render)
#
# e.g.:
#
# Method: helpHex
#
# 0x00:  00 00 12 04 00 00 00 00 00 00 03 7F FF FF FF 00    ................
# 0x10:  04 00 10 00 00 00 06 00 00 20 00 00 00 04 08 00    ......... ......
# 0x20:  00 00 00 00 00 0F 00 01 00 00 62 07 00 00 00 00    ..........b.....
# 0x30:  00 00 00 00 00 00 00 00 01 48 54 54 50 2F 32 20    .........HTTP/2  # nb: Trailing space
# 0x40:  63 6C 69 65 6E 74 20 70 72 65 66 61 63 65 20 73    client preface s
# 0x50:  74 72 69 6E 67 20 6D 69 73 73 69 6E 67 20 6F 72    tring missing or
# 0x60:  20 63 6F 72 72 75 70 74 2E 20 48 65 78 20 64 75     corrupt. Hex du
# 0x70:  6D 70 20 66 6F 72 20 72 65 63 65 69 76 65 64 20    mp for received  # nb: Trailing space
# 0x80:  62 79 74 65 73 3A 20 34 38 34 35 34 63 35 30 30    bytes: 48454c500
# 0x90:  64 30 61                                           d0a

if( "HTTP/2 client preface string missing or corrupt. Hex dump for received bytes:" >< rbinstr_space ) {
  service_register( port:port, proto:"grpc", message:"A gRPC service seems to be running on this port." );
  log_message( port:port, data:"A gRPC service seems to be running on this port." );
  exit( 0 );
}

# nb: Keep qotd at the end of the list, as it may generate false detection
if( r =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$' || egrep( pattern:"^[A-Za-z. -]+\([0-9-]+\)", string:r ) ) {
  replace_kb_item( name:"qotd/tcp/" + port + "/banner", value:chomp( banner ) );
  service_register( port:port, proto:"qotd" );
  log_message( port:port, data:"A qotd (Quote of the Day) service seems to be running on this port." );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if (! r0) unknown_banner_set(port: port, banner: r);

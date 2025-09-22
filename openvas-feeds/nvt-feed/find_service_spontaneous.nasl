# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108747");
  script_version("2024-08-30T15:39:02+0000");
  script_tag(name:"last_modification", value:"2024-08-30 15:39:02 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"creation_date", value:"2020-04-14 11:32:00 +0000 (Tue, 14 Apr 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection from 'spontaneous' Banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It evaluates 'spontaneous' banners sent by the remaining unknown
  services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("ssh_func.inc");

if( ! port = get_kb_item( "Services/unknown" ) )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

key = "FindService/tcp/" + port + "/spontaneous";
banner = get_kb_item( key );
if( strlen( banner ) <= 0 ) {
  # nb: At least STelnet of Huawei VRP devices doesn't respond to the banner
  # grabbing of nasl_builtin_find_service.c but providing a banner with a
  # separate recv_line() so we're trying to grab it here again.

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  banner = recv_line( socket:soc, length:4096 );
  close( soc );

  if( strlen( banner ) > 0 ) {
    set_kb_item( name:key, value:banner );
    bannerhex = hexstr( banner );
    if( '\0' >< banner )
      set_kb_item( name:key + "Hex", value:bannerhex );
  }
} else {
  bannerhex = hexstr( banner );
}

if( strlen( banner ) <= 0 )
  exit( 0 );

if( banner =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+' ) {
  service_register( port:port, proto:"fake-identd" );
  set_kb_item( name:"fake_identd/" + port, value:TRUE );
  exit( 0 );
}

# Running on 6600, should be handled already later by find_service2.nasl
# but the banner sometimes is also coming in "spontaneous".
# 00: 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31    <?xml version="1
# 10: 2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 49 53    .0" encoding="IS
# 20: 4f 2d 38 38 35 39 2d 31 22 20 73 74 61 6e 64 61    O-8859-1" standa
# 30: 6c 6f 6e 65 3d 22 79 65 73 22 3f 3e 0a 3c 21 44    lone="yes"?>.<!D
# 40: 4f 43 54 59 50 45 20 47 41 4e 47 4c 49 41 5f 58    OCTYPE GANGLIA_X
# 50: 4d 4c 20 5b 0a 20 20 20 3c 21 45 4c 45 4d 45 4e    ML [.   <!ELEMEN
# 60: 54 20 47 41 4e 47 4c 49 41 5f 58 4d 4c 20 28 47    T GANGLIA_XML (G
# 70: 52 49 44 29 2a 3e 0a 20 20 20 20 20 20 3c 21 41    RID)*>.      <!A
if( match( string:banner, pattern:'<?xml version=*' ) && " GANGLIA_XML " >< banner &&
    "ATTLIST HOST GMOND_STARTED" >< banner ) {
  service_register( port:port, proto:"gmond" );
  log_message( port:port, data:"Ganglia monitoring daemon seems to be running on this port" );
  exit( 0 );
}

if( match( string:banner, pattern:'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *' ) ) {
  service_report( port:port, svc:"smsc" );
  exit( 0 );
}

# 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
# 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
# 20: 0a .
if( ereg( pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:banner ) ) {
  service_report( port:port, svc:"daytime" );
  exit( 0 );
}

# Possible outputs:
# |/dev/hdh|Maxtor 6Y160P0|38|C|
# |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
if( banner =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$' ) {
  service_report( port:port, svc:"hddtemp" );
  exit( 0 );
}

if( match( string:banner, pattern:'220 *FTP Server ready\r\n', icase:TRUE ) ||
    match( string:banner, pattern:'220 *FTP Server ready.\r\n', icase:TRUE ) ) { # e.g. 220 AP9630 Network Management Card AOS v6.0.6 FTP server ready.
  service_report( port:port, svc:"ftp" );
  exit( 0 );
}

# 0x00:  22 49 4D 50 4C 45 4D 45 4E 54 41 54 49 4F 4E 22    "IMPLEMENTATION"
# 0x10:  20 22 43 79 72 75 73 20 74 69 6D 73 69 65 76 65     "Cyrus timsieve
# 0x20:  64 20 76 32 2E 34 2E 31 37 2D 46 65 64 6F 72 61    d v2.4.17-Fedora
# 0x30:  2D 52 50 4D 2D 32 2E 34 2E 31 37 2D 31 33 2E 65    -RPM-2.4.17-13.e
# 0x40:  6C 37 22 0D 0A                                     l7"..
#
# or:
#
# 0x00:  22 49 4D 50 4C 45 4D 45 4E 54 41 54 49 4F 4E 22    "IMPLEMENTATION"
# 0x10:  20 22 41 70 61 63 68 65 20 4D 61 6E 61 67 65 53     "Apache ManageS
# 0x20:  69 65 76 65 20 76 31 2E 30 22 0D 0A                ieve v1.0"..
#
# nb: As we're only getting a "single" line back in this VT (on purpose) and we thus can't check for
# "SIEVE" this regex is a little bit more strict then the more generic one in find_service2.nasl...
if( egrep( string:banner, pattern:'^"IMPLEMENTATION" "(Cyrus timsieved|Apache ManageSieve)[^"]*"', icase:FALSE ) ) {
  service_register( port:port, proto:"sieve", message:"A Sieve mail filter daemon seems to be running on this port." );
  log_message( port:port, data:"A Sieve mail filter daemon seems to be running on this port." );
  exit( 0 );
}

# I'm not sure it should go here or in find_service2...
if( match( string:banner, pattern:'220 Axis Developer Board*' ) ) {
  service_report( port:port, svc:"axis-developer-board" );
  exit( 0 );
}

if( match( string:banner, pattern:'  \x5f\x5f\x5f           *Copyright (C) * Eggheads Development Team' ) ) {
  service_report( port:port, svc:"eggdrop" );
  exit( 0 );
}

# Music Player Daemon from www.musicpd.org
if( ereg( string:banner, pattern:'^OK MPD [0-9.]+\n' ) ) {
  service_report( port:port, svc:"mpd" );
  exit( 0 );
}

# nb: See find_service1.nasl as well
if( egrep( pattern:"^OK WorkgroupShare.+server ready", string:banner, icase:FALSE ) ) {
  replace_kb_item( name:"workgroupshare/" + port + "/banner", value:chomp( banner ) );
  service_report( port:port, svc:"WorkgroupShare" );
  exit( 0 );
}

# Eudora Internet Mail Server ACAP server.
if( "* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" >< banner ) {
  service_report( port:port, svc:"acap" );
  exit( 0 );
}

# Sophos Remote Messaging / Management Server
if( "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< banner ) {
  service_register( port:port, proto:"sophos_rms", message:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  log_message( port:port, data:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  exit( 0 );
}

if( banner =~ '^\\* *BYE ' ) {
  service_report( port:port, svc:"imap", banner:banner, message:"The IMAP server rejects connection from our host. We cannot test it." );
  log_message( port:port, data:"The IMAP server rejects connection from our host. We cannot test it." );
  exit( 0 );
}

# General case should be handled by find_service_3digits
if( match( string:banner, pattern:'200 CommuniGatePro PWD Server * ready*' ) ) {
  service_report( port:port, svc:"pop3pw" );
  exit( 0 );
}

# Should be handled by find_service already
if( banner =~ "^RFB [0-9]") {
  service_report( port:port, svc:"vnc" );
  replace_kb_item( name:"vnc/banner/" + port, value:banner );
  exit( 0 );
}

# https://www.iana.org/assignments/beep-parameters/beep-parameters.xhtml
# 0x00:  52 50 59 20 30 20 30 20 2E 20 30 20 31 30 32 0D    RPY 0 0 . 0 102.
# 0x10:  0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61    .Content-Type: a
# 0x20:  70 70 6C 69 63 61 74 69 6F 6E 2F 62 65 65 70 2B    pplication/beep+
# 0x30:  78 6D 6C 0D 0A 0D 0A 3C 67 72 65 65 74 69 6E 67    xml....<greeting
# 0x40:  3E 3C 70 72 6F 66 69 6C 65 20 75 72 69 3D 22 68    ><profile uri="h
# 0x50:  74 74 70 3A 2F 2F 69 61 6E 61 2E 6F 72 67 2F 62    ttp://iana.org/b
# 0x60:  65 65 70 2F 54 4C 53 22 2F 3E 3C 2F 67 72 65 65    eep/TLS"/></gree
# 0x70:  74 69 6E 67 3E 0D 0A 45 4E 44 0D 0A                ting>..END..
#
# nb: beep/xmlrpc has application/xml as the Content-Type so using some
# different patterns here.
# nb: Have seen a response to http_get and spontaneuos for this so the same check is
# done in find_service1.nasl as well. Please keep both in sync.
if( ( banner =~ "^RPY [0-9] [0-9]" && "Content-Type: application/" >< banner ) ||
    ( "<profile uri=" >< banner && "http://iana.org/beep/" >< banner ) ||
    "Content-Type: application/beep" >< banner ) {
  service_register( port:port, proto:"beep", message:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  exit( 0 );
}

if( ssh_verify_server_ident( data:banner ) ) {
  service_register( port:port, proto:"ssh", message:"A SSH service seems to be running on this port." );
  log_message( port:port, data:"A SSH service seems to be running on this port." );
  replace_kb_item( name:"SSH/server_banner/" + port, value:chomp( banner ) );
}

# Seen on port 8888/tcp
# 0x00:  AC ED 00 05 73 72 00 35 6A 61 76 61 78 2E 6D 61    ....sr.5javax.ma
# 0x10:  6E 61 67 65 6D 65 6E 74 2E 72 65 6D 6F 74 65 2E    nagement.remote.
# 0x20:  6D 65 73 73 61 67 65 2E 48 61 6E 64 73 68 61 6B    message.Handshak
# 0x30:  65 42 65 67 69 6E 4D 65 73 73 61 67 65 04 13 DF    eBeginMessage...
# 0x40:  2C 84 8B CE 36 02 00 02 4C 00 08 70 72 6F 66 69    ,...6...L..profi
# 0x50:  6C 65 73 74 00 12 4C 6A 61 76 61 2F 6C 61 6E 67    lest..Ljava/lang
# 0x60:  2F 53 74 72 69 6E 67 3B 4C 00 07 76 65 72 73 69    /String;L..versi
# 0x70:  6F 6E 71 00 7E 00 01 78 70 70 74 00 03 31 2E 30    onq.~..xppt..1.0
#
# Seen on port 8000/tcp
# 0x00:  AC ED 00 05                                      ....
#
# From https://nytrosecurity.com/2018/05/30/understanding-java-deserialization/:
# AC ED: Data starts with the binary "AC ED" - this is the "magic number" that identifies serialized data, so all serialized data will start with this value
# 00 05: Serialization protocol version "00 05"
# 73: The type of the object, for a "String" this is 74
# 72 00: The length of the string
if( bannerhex =~ "^ACED....(.+|$)" ) {
  service_register( port:port, proto:"java-rmi", message:"A Java RMI service seems to be running on this port." );
  log_message( port:port, data:"A Java RMI service seems to be running on this port." );
}

# nb:
# - Seen on port 1777/tcp
# - reporting from unknown_services.nasl / gb_unknown_os_service_reporting.nasl before this
#   detection got introduced
# - Similar pattern is used in find_service1.nasl just to be sure to catch the services at two
#   places if it doesn't response to one probe (e.g. overloaded during "full" scans)
#
# Method: spontaneousHex
#
# 0x0000:  00 00 01 60 00 00 00 25 00 00 01 2B 00 00 00 00    ...`...%...+....
# 0x0010:  00 00 00 02 00 00 00 05 00 00 00 01 68 2E 6D 69    ............h.mi
# 0x0020:  64 30 00 00 00 02 00 00 00 05 00 00 00 02 68 2E    d0............h.
# 0x0030:  63 6D 64 31 38 00 00 00 02 00 00 00 05 00 00 00    cmd18...........
# 0x0040:  03 70 2E 72 65 76 33 30 38 00 00 00 08 00 00 00    .p.rev308.......
# 0x0050:  06 00 00 00 1C 70 2E 67 75 69 64 30 30 35 30 35    .....p.guid00505
# 0x0060:  36 38 37 41 45 36 38 36 34 46 42 32 41 33 31 30    687AE6864FB2A310
# 0x0070:  30 30 30 30 30 32 35 00 00 00 02 00 00 00 09 00    0000025.........
# 0x0080:  00 00 01 70 2E 65 6E 63 72 79 70 74 30 00 00 00    ...p.encrypt0...
# 0x0090:  02 00 00 00 09 00 00 00 01 70 2E 65 6E 63 6D 65    .........p.encme
# 0x00A0:  74 68 30 00 00 00 06 00 00 00 04 00 00 00 12 70    th0............p
# 0x00B0:  2E 69 70 31 39 32 2E 31 36 38 2E 37 39 2E 34 3A    .ip192.168.79.4:
# 0x00C0:  35 34 36 37 31 00 00 00 01 00 00 00 05 00 00 00    54671...........
# 0x00D0:  05 70 2E 61 6D 63 36 2E 34 2E 30 00 00 00 09 00    .p.amc6.4.0.....
# 0x00E0:  00 00 09 00 00 00 0D 70 2E 65 6E 63 70 72 6F 74    .......p.encprot
# 0x00F0:  30 3B 30 3B 30 3B 30 3B 30 3B 30 3B 30 00 00 00    0;0;0;0;0;0;0...
# 0x0100:  07 00 00 00 05 00 00 00 0A                         .........
if( bannerhex =~ "702E67756964.+656E6370726F74.+7000000050000000a$" ) {
  service_register( port:port, proto:"avalanche_mds", message:"An Ivanti Avalanche Mobile Device Server service seems to be running on this port." );
  log_message( port:port, data:"An Ivanti Avalanche Mobile Device Server service seems to be running on this port." );
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
# nb: See find_service1.nasl and find_service2.nasl as well
#
if( "(Thread" >< banner && ( "Notify Wlan Link " >< banner ||
    "Notify Eth Link " >< banner ||
    "Received unknown command on socket" >< banner ||
    "fsfsFlashFileHandleOpen" >< banner ||
    "Found existing handle " >< banner ||
    "After waiting approx. " >< banner ||
    "Timer fired at " >< banner ||
    "ControlSocketServerInstructClientToLeave" >< banner ||
    ( "AUDSYN" >< banner && "audioSyncInit" >< banner ) ||
    ( "WFSAPI" >< banner && "File not found" >< banner ) ) ) {
  service_register( port:port, proto:"wifiradio-setup", message:"A WiFi radio setup service seems to be running on this port." );
  log_message( port:port, data:"A WiFi radio setup service seems to be running on this port." );
  exit( 0 );
}

# HSQLDB JDBC Network Listener.
if( "HSQLDB JDBC Network Listener" >< banner ) {
  service_register( port:port, proto:"hsqldb", message:"An HSQLDB service seems to be running on this port.");
  log_message( port:port, data:"An HSQLDB service seems to be running on this port.");
  exit( 0 );
}

# Keep qotd at the end of the list, as it may generate false detection
if( banner =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$' ) {
  replace_kb_item( name:"qotd/tcp/" + port + "/banner", value:chomp( banner ) );
  service_register( port:port, proto:"qotd", message:"A qotd (Quote of the Day) service seems to be running on this port." );
  log_message( port:port, data:"A qotd (Quote of the Day) service qotd seems to be running on this port." );
  exit( 0 );
}

exit( 0 );

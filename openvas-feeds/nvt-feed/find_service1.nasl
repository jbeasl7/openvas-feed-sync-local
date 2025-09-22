# SPDX-FileCopyrightText: 2005 Michel Arboi
# SPDX-FileCopyrightText: New detection methods / pattern / code since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17975");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'GET' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service_spontaneous.nasl",
                      "cifs445.nasl", "apache_SSL_complain.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It sends a HTTP 'GET' request to the remaining unknown services and
  tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("string_hex_func.inc");
include("global_settings.inc");
include("dump.inc");
include("sip.inc");

if( ! port = get_kb_item( "Services/unknown" ) )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

k = "FindService/tcp/" + port + "/get_http";
r = get_kb_item( k + "Hex" );
if( strlen( r ) > 0 )
  r = hex2raw( s:r );
else
  r = get_kb_item( k );

r_len = strlen( r );
if( r_len == 0 ||
    # nb: Some HTTP/0.9 systems (e.g. D-Link DSL-G225) seems to provide a larger body which is
    # truncated and thus not including the trailing "</html>" so we're receiving the whole body in
    # this case.
    ( r_len > 0 && r =~ '^[ \t\r\n]*<HTML>' && r !~ "</HTML>" )
  ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  send( socket:soc, data:'GET / HTTP/1.0\r\n\r\n' );
  r = recv( socket:soc, length:4096 );
  # nb: If not fully received try once more in this case (Mainly for HTTP/0.9 systems)...
  if( r && r =~ '^[ \t\r\n]*<HTML>' && r !~ "</HTML>$" ) {
    debug_print( "Not all HTTP data received from service on port ", port, ", trying to receive more data..." );
    r2 = recv( socket:soc, length:4096 );
    if( r2 )
      r += r2;
  }

  close( soc );

  r_len = strlen( r );
  if( r_len == 0 ) {
    debug_print( 'Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n' );
    exit( 0 );
  }

  set_kb_item( name:k, value:r );
  rhexstr = hexstr( r );
  if( '\0' >< r )
    set_kb_item( name:k + "Hex", value:rhexstr );
} else {
  rhexstr = hexstr( r );
}

rbinstr_space = bin2string( ddata:r, noprint_replacement:' ' );
rbinstr_nospace = bin2string( ddata:r );

# aka HTTP/0.9
if( r =~ '^[ \t\r\n]*<HTML>.*</HTML>' ) {
  service_report( port:port, svc:"www", banner:r );
  exit( 0 );
}

if( r == '[TS]\r\n') {
  service_report( port:port, svc:"teamspeak-tcpquery", banner:r );
  exit( 0 );
}

if( r == 'gethostbyaddr: Error 0\n' ) {
  service_register( port:port, proto:"veritas-netbackup-client", message:"Veritas NetBackup Client Service is running on this port" );
  log_message( port:port, data:"Veritas NetBackup Client Service is running on this port" );
  exit( 0 );
}

if( "GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r ||
    "GET/HTTP/1.0 : ERROR : INVALID-PORT" >< r ) { # nb: Some auth services on e.g. Windows are responding with such a different response
  service_report( port:port, svc:"auth", banner:r );
  exit( 0 );
}

if( 'Host' >< r && 'is not allowed to connect to this' >< r && ( "mysql">< tolower( r ) || "mariadb" >< tolower( r ) ) ) {
  if( "mysql">< tolower( r ) ) {
    text = "A MySQL";
  } else if( "mariadb" >< tolower( r ) ) {
    text = "A MariaDB";
  } else {
    text = "A MySQL/MariaDB";
  }
  service_register( port:port, proto:"mysql", message:text + " server seems to be running on this port but it rejects connection from the scanner." ); # or wrapped?
  log_message( port:port, data:text + " server seems to be running on this port but it rejects connection from the scanner." );
  exit( 0 );
}

# The full message is:
# Host '10.10.10.10' is blocked because of many connection errors. Unblock with 'mysqladmin flush-hosts'
if( "Host" >< r && " is blocked " >< r && "mysqladmin flush-hosts" >< r ) {
  service_register( port:port, proto:"mysql", message:"A MySQL/MariaDB server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
  log_message( port:port, data:"A MySQL server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
  exit( 0 );
}

#0x00:  4A 00 00 00 0A 35 2E 37 2E 31 36 00 68 49 72 00    J....5.7.16.hIr.
#0x10:  6A 5F 26 1F 4A 52 20 5B 00 FF FF 08 02 00 FF C1    j_&.JR [........
#0x20:  15 00 00 00 00 00 00 00 00 00 00 50 4D 51 64 16    ...........PMQd.
#0x30:  3D 50 19 35 1E 48 46 00 6D 79 73 71 6C 5F 6E 61    =P.5.HF.mysql_na
#0x40:  74 69 76 65 5F 70 61 73 73 77 6F 72 64 00 1B 00    tive_password...
#0x50:  00 01 FF 84 04 47 6F 74 20 70 61 63 6B 65 74 73    .....Got packets
#0x60:  20 6F 75 74 20 6F 66 20 6F 72 64 65 72              out of order

# or

#0x00:  3E 00 00 00 0A 35 2E 31 2E 37 31 2D 63 6F 6D 6D    >....5.1.71-comm
#0x10:  75 6E 69 74 79 00 17 ED 1F 00 29 64 41 55 68 2E    unity.....)dAUh.
#0x20:  46 58 00 FF F7 08 02 00 00 00 00 00 00 00 00 00    FX..............
#0x30:  00 00 00 00 00 69 25 7A 59 31 26 67 58 61 5D 33    .....i%zY1&gXa]3
#0x40:  24 00 1B 00 00 01 FF 84 04 47 6F 74 20 70 61 63    $........Got pac
#0x50:  6B 65 74 73 20 6F 75 74 20 6F 66 20 6F 72 64 65    kets out of orde
#0x60:  72                                                 r

# SphinxQL of the Sphinx search server is responding with something like the following below
# which would make this detection to wrongly detect a SphinxQL service as MySQL.
#
# 3.0.2 e3d296ef@190531 release
#
# 0x00:  61 00 00 00 0A 33 2E 30 2E 32 20 65 33 64 32 39    a....3.0.2 e3d29
# 0x10:  36 65 66 40 31 39 30 35 33 31 20 72 65 6C 65 61    6ef@190531 relea
# 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
# 0x30:  08 82 21 02 00 08 00 15 00 00 00 00 00 00 00 00    ..!.............
# 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00 6D    ...............m
# 0x50:  79 73 71 6C 5F 6E 61 74 69 76 65 5F 70 61 73 73    ysql_native_pass
# 0x60:  77 6F 72 64 00                                     word.
#
if( rbinstr_space !~ "[0-9.]+ [0-9a-z]+@[0-9a-z]+ release" &&
    ( ( "mysql_native_password" >< r && "Got packets out of order" >< r ) ||
        "001b000001ff8404476f74207061636b657473206f7574206f66206f72646572" >< rhexstr ||
        "006d7973716c5f6e61746976655f70617373776f726400" >< rhexstr ) ) {
  service_register( port:port, proto:"mysql", message:"A MySQL/MariaDB server seems to be running on this port." );
  log_message( port:port, data:"A MySQL/MariaDB server seems to be running on this port." );
  exit( 0 );
}

# JNB30........
# .4....I.n.v.a.l.i.d. .r.e.q.u.e.s.t.:. . .i.n.v.a.l.i.d. .j.n.b.b.i.n.a.r.y.
# [...]
if( r =~ "^JNB30" && ord( r[5] ) == 14 && ord( r[6] == 3 ) ) {
  service_register( port:port, proto:"jnbproxy", message:"ColdFusion jnbproxy is running on this port." );
  log_message( port:port, data:"ColdFusion jnbproxy is running on this port." );
  exit( 0 );
}

if( "Asterisk Call Manager" >< r ) {
  service_register( port:port, proto:"asterisk", message:"An Asterisk Call Manager server is running on this port." );
  log_message( port:port, data:"An Asterisk Call Manager server is running on this port." );
  exit( 0 );
}

# Taken from find_service2.nasl
if( r_len == 3 && ( r[2] == '\x10' || # same test as find_service
                   r[2] == '\x0b' ) ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' ) {
  service_register( port:port, proto:"msdtc", message:"A MSDTC server seems to be running on this port");
  log_message( port:port, data:"A MSDTC server seems to be running on this port");
  exit( 0 );
}

# It seems that MS DTC banner is longer that 3 bytes, when we properly handle
# null bytes
# For example:
# 00: 90 a2 0a 00 80 94 ..
if( (r_len == 5 || r_len == 6) && r[3] == '\0' &&
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0' ) {
  service_register( port:port, proto:"msdtc", message:"A MSDTC server seems to be running on this port");
  log_message( port:port, data:"A MSDTC server seems to be running on this port");
  exit( 0 );
}

# lpd [@<redacted>]: Print-services are not available to your host (<redacted>).
if( r == '\x01Permission denied' || ( "lpd " >< r && "Print-services" >< r ) ) {
  service_report( port:port, svc:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^EVENT" && "WatchGuard Authentication Gateway SSO agent" >< r ) {
  service_report( port:port, svc:"telnet", message:"A WatchGuard Authentication Gateway SSO agent service seems to be running on this port." );
  log_message( port:port, data:"A WatchGuard Authentication Gateway SSO agent service seems to be running on this port." );
  exit( 0 );
}

#### Double check: all this should be handled by find_service.nasl ####

if( r == 'GET / HTTP/1.0\r\n\r\n' ) {
  service_report( port:port, svc:"echo", banner:r );
  exit( 0 );
}

# Should we excluded port=5000...? (see find_service.c)
if( r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ' ) {
  service_report( port:port, svc:"www", banner:r );
  exit( 0 );
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if( r =~ '^[0-9][0-9][0-9]-?[ \t]' ) {
  debug_print('"3 digits" found on port ', port, ' in response to GET\n' );
  service_register( port:port, proto:"three_digits" );
  exit( 0 );
}

if( r =~ "^RFB [0-9]" ) {
  service_report( port:port, svc:"vnc" );
  replace_kb_item( name:"vnc/banner/" + port , value:r );
  exit( 0 );
}

if( match( string:r, pattern:"Language received from client:*Setlocale:*" ) ) {
  service_report( port:port, svc:"websm" );
  exit( 0 );
}

# invalid command (code=12064, len=1414541105)
# nb: Don't use a ^ anchor, the banner is located within some binary blob.
# nb: see sw_sphinxsearch_detect.nasl as well
if( banner = egrep( string:rbinstr_space, pattern:"invalid command \(code=([0-9]+), len=([0-9]+)\)" ) ) {
  service_register( port:port, proto:"sphinxapi", message:"A Sphinx search server seems to be running on this port" );
  log_message( port:port, data:"A Sphinx search server seems to be running on this port" );
  set_kb_item( name:"sphinxsearch/" + port + "/sphinxapi/banner", value:banner );
  exit( 0 );
}

# Examples:
# 2.0.9-id64-release (rel20-r4115)
# 2.1.2-id64-release (r4245)
# 2.0.4-release (r3135)
# 2.2.11-id64-release (95ae9a6)
# 2.8.0 4006794b@190128 release
# 3.0.2 e3d296ef@190531 release
#
# Binary:
# 0x00:  4B 00 00 00 0A 32 2E 38 2E 30 20 34 30 30 36 37    K....2.8.0 40067
# 0x10:  39 34 62 40 31 39 30 31 32 38 20 72 65 6C 65 61    94b@190128 relea
# 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
# 0x30:  08 82 21 02 00 00 00 00 00 00 00 00 00 00 00 00    ..!.............
# 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00       ...............
#
# 0x00:  61 00 00 00 0A 33 2E 30 2E 32 20 65 33 64 32 39    a....3.0.2 e3d29
# 0x10:  36 65 66 40 31 39 30 35 33 31 20 72 65 6C 65 61    6ef@190531 relea
# 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
# 0x30:  08 82 21 02 00 08 00 15 00 00 00 00 00 00 00 00    ..!.............
# 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00 6D    ...............m
# 0x50:  79 73 71 6C 5F 6E 61 74 69 76 65 5F 70 61 73 73    ysql_native_pass
# 0x60:  77 6F 72 64 00
#
# 0x00:  48 00 00 00 0A 32 2E 30 2E 38 2D 69 64 36 34 2D    H....2.0.8-id64-
# 0x10:  72 65 6C 65 61 73 65 20 28 72 33 38 33 31 29 00    release (r3831).
# 0x20:  01 00 00 00 01 02 03 04 05 06 07 08 00 08 82 21    ...............!
# 0x30:  02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01    ................
# 0x40:  02 03 04 05 06 07 08 09 0A 0B 0C 0D                ............
#
# nb: see sw_sphinxsearch_detect.nasl as well
if( r_len > 10 && r[1] == '\0' && r[2] == '\0' && r[3] == '\0' &&
    eregmatch( string:rbinstr_space, pattern:"^.\s{4}[0-9.]+(-(id[0-9]+-)?release \([0-9a-z-]+\)| [0-9a-z]+@[0-9a-z]+ release)" ) ) {
  service_register( port:port, proto:"sphinxql", message:"A Sphinx search server (MySQL listener) seems to be running on this port" );
  log_message( port:port, data:"A Sphinx search server (MySQL listener) seems to be running on this port" );
  set_kb_item( name:"sphinxsearch/" + port + "/sphinxql/banner", value:rbinstr_space );
  exit( 0 );
}

if( match( string:r, pattern:"*<stream:stream*xmlns:stream='http://etherx.jabber.org/streams'*" ) ) {
  if( "jabber:server" >< r ) {
    service_register( port:port, proto:"xmpp-server", message:"A XMPP server-to-server service seems to be running on this port" );
    log_message( port:port, data:"A XMPP server-to-server service seems to be running on this port" );
    exit( 0 );
  } else if( "jabber:client" >< r ) {
    service_register( port:port, proto:"xmpp-client", message:"A XMPP client-to-server service seems to be running on this port" );
    log_message( port:port, data:"A XMPP client-to-server service seems to be running on this port" );
    exit( 0 );
  } else {
    log_message( port:port, data:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    service_register( port:port, proto:"xmpp-server", message:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    service_register( port:port, proto:"xmpp-client", message:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    exit( 0 );
  }
}

if( "Active Internet connections" >< r || "Active connections" >< r ) {
  service_register( port:port, proto:"netstat", message:"A netstat service seems to be running on this port." );
  log_message( port:port, data:"A netstat service seems to be running on this port." );
  exit( 0 );
}

if( "obby_welcome" >< r ) {
  service_register( port:port, proto:"obby", message:"A obby service seems to be running on this port." );
  log_message( port:port, data:"A obby service seems to be running on this port." );
  exit( 0 );
}

if( match( string:r, pattern:"*OK Cyrus IMSP version*ready*" ) ) {
  service_register( port:port, proto:"imsp", message:"A Cyrus IMSP service seems to be running on this port." );
  log_message( port:port, data:"A Cyrus IMSP service seems to be running on this port." );
  exit( 0 );
}

# e.g.  RESPONSE/None/53/application/json: {"status": 554, "message": "Unparsable message body"}
if( match( string:r, pattern:'RESPONSE/None/*/application/json:*{"status": *, "message": "*"}' ) ) {
  service_register( port:port, proto:"umcs", message:"A Univention Management Console Server service seems to be running on this port." );
  log_message( port:port, data:"A Univention Management Console Server service seems to be running on this port." );
  exit( 0 );
}

if( "DRb::DRbConnError" >< rbinstr_nospace ) {
  service_register( port:port, proto:"drb", message:"A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
  log_message( port:port, data:"A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
  exit( 0 );
}

# 9290 for raw scanning to peripherals with IEEE 1284.4 specifications. On three port HP JetDirects, the scan ports are 9290, 9291, and 9292.
# (When you connect to a raw scan port, the scan gateway sends back "00" if the connection to the peripheral's scan service was successful, "01"
# if somebody else is using it, and "02" if some other error, for example, the supported peripheral is not connected. Ports 9220, 9221, and 9222
# are the generic scan gateway ports currently only usable on 1284.4 peripherals.)
# Source: https://support.hp.com/us-en/document/c02480766
if( port =~ "^929[0-2]$" && r =~ "^0[0-2]$") {
  service_register( port:port, proto:"iee-rsgw", message:"A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
  log_message( port:port, data:"A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
  exit( 0 );
}

# Seen for/on JetDirect lpd.
# nb: See find_service2.nasl as well. This was just added there as a fallback if this first
# detection / connection has some hiccup.
if( port == 515 && rhexstr =~ "^ff$" ) {
  service_register( port:port, proto:"lpd", message:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Line Printer Daemon (LPD) protocol seems to be running on this port." );
  exit( 0 );
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
# nb: The same is also checked in find_service2.nasl and find_service_spontaneous.nasl but sometimes
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

# Sophos Remote Messaging / Management Server
if( "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r ) {
  service_register( port:port, proto:"sophos_rms", message:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  log_message( port:port, data:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  exit( 0 );
}

if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  replace_kb_item( name:"checkmk_agent/banner/" + port, value:r );
  service_register( port:port, proto:"checkmk_agent", message:"A Checkmk Agent seems to be running on this port." );
  log_message( port:port, data:"A Checkmk Agent seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^\.NET" && ( "customErrors" >< r || "RemotingException" >< r ) ) {
  service_register( port:port, proto:"remoting", message:"A .NET remoting service seems to be running on this port." );
  log_message( port:port, data:"A .NET remoting service seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^-ERR wrong number of arguments for 'get' command" || egrep( string:r, pattern:"^-ERR unknown command 'Host:'" ) ||
    r =~ "^-DENIED Redis is running in protected mode" ) {
  service_register( port:port, proto:"redis", message:"A Redis server seems to be running on this port." );
  log_message( port:port, data:"A Redis server seems to be running on this port." );
  exit( 0 );
}

# 0x00:  41 4D 51 50 03 01 00 00 41 4D 51 50 00 01 00 00    AMQP....AMQP....
# 0x10:  00 00 00 19 02 00 00 00 00 53 10 C0 0C 04 A1 00    .........S......
# 0x20:  40 70 FF FF FF FF 60 7F FF 00 00 00 60 02 00 00    @p....`.....`...
# 0x30:  00 00 53 18 C0 53 01 00 53 1D C0 4D 02 A3 11 61    ..S..S..S..M...a
# 0x40:  6D 71 70 3A 64 65 63 6F 64 65 2D 65 72 72 6F 72    mqp:decode-error
# 0x50:  A1 37 43 6F 6E 6E 65 63 74 69 6F 6E 20 66 72 6F    .7Connection fro
# 0x60:  6D 20 63 6C 69 65 6E 74 20 75 73 69 6E 67 20 75    m client using u
# 0x70:  6E 73 75 70 70 6F 72 74 65 64 20 41 4D 51 50 20    nsupported AMQP
# 0x80:  61 74 74 65 6D 70 74 65 64                         attempted

if( "Connection from client using unsupported AMQP attempted" >< r || "amqp:decode-error" >< r ) {
  service_register( port:port, proto:"amqp", message:"A AMQP service seems to be running on this port." );
  log_message( port:port, data:"An AMQP service seems to be running on this port." );
  exit( 0 );
}

# 0x0000:  00 00 01 87 01 41 63 74 69 76 65 4D 51 00 00 00    .....ActiveMQ...
# 0x0010:  0C 01 00 00 01 75 00 00 00 0C 00 11 54 63 70 4E    .....u......TcpN
# 0x0020:  6F 44 65 6C 61 79 45 6E 61 62 6C 65 64 01 01 00    oDelayEnabled...
# 0x0030:  12 53 69 7A 65 50 72 65 66 69 78 44 69 73 61 62    .SizePrefixDisab
# 0x0040:  6C 65 64 01 00 00 09 43 61 63 68 65 53 69 7A 65    led....CacheSize
# 0x0050:  05 00 00 04 00 00 0C 50 72 6F 76 69 64 65 72 4E    .......ProviderN
# 0x0060:  61 6D 65 09 00 08 41 63 74 69 76 65 4D 51 00 11    ame...ActiveMQ..
# 0x0070:  53 74 61 63 6B 54 72 61 63 65 45 6E 61 62 6C 65    StackTraceEnable
# 0x0080:  64 01 01 00 0F 50 6C 61 74 66 6F 72 6D 44 65 74    d....PlatformDet
# 0x0090:  61 69 6C 73 09 00 50 4A 56 4D 3A 20 31 2E 38 2E    ails..PJVM: 1.8.
# 0x00A0:  30 5F 31 34 31 2C 20 32 35 2E 31 34 31 2D 62 31    0_141, 25.141-b1
# 0x00B0:  35 2C 20 4F 72 61 63 6C 65 20 43 6F 72 70 6F 72    5, Oracle Corpor
# 0x00C0:  61 74 69 6F 6E 2C 20 4F 53 3A 20 4C 69 6E 75 78    ation, OS: Linux
# 0x00D0:  2C 20 34 2E 31 33 2E 30 2D 31 2D 61 6D 64 36 34    , 4.13.0-1-amd64
# 0x00E0:  2C 20 61 6D 64 36 34 00 0C 43 61 63 68 65 45 6E    , amd64..CacheEn
# 0x00F0:  61 62 6C 65 64 01 01 00 14 54 69 67 68 74 45 6E    abled....TightEn
# 0x0100:  63 6F 64 69 6E 67 45 6E 61 62 6C 65 64 01 01 00    codingEnabled...
# 0x0110:  0C 4D 61 78 46 72 61 6D 65 53 69 7A 65 06 00 00    .MaxFrameSize...
# 0x0120:  00 00 06 40 00 00 00 15 4D 61 78 49 6E 61 63 74    ...@....MaxInact
# 0x0130:  69 76 69 74 79 44 75 72 61 74 69 6F 6E 06 00 00    ivityDuration...
# 0x0140:  00 00 00 00 75 30 00 20 4D 61 78 49 6E 61 63 74    ....u0. MaxInact
# 0x0150:  69 76 69 74 79 44 75 72 61 74 69 6F 6E 49 6E 69    ivityDurationIni
# 0x0160:  74 61 6C 44 65 6C 61 79 06 00 00 00 00 00 00 27    talDelay.......'
# 0x0170:  10 00 0F 50 72 6F 76 69 64 65 72 56 65 72 73 69    ...ProviderVersi
# 0x0180:  6F 6E 09 00 06 35 2E 31 34 2E 35                   on...5.14.5

if( "ActiveMQ" >< r && ( "PlatformDetails" >< r || "StackTraceEnable" >< r || "ProviderVersion" >< r || "TcpNoDelayEnabled" >< r ) ) {
  # nb: Set the response for later use in gsf/gb_apache_activemq_jms_detect.nasl
  set_kb_item( name:"ActiveMQ/JMS/banner/" + port, value:rbinstr_nospace );
  service_register( port:port, proto:"activemq_jms", message:"A ActiveMQ JMS service seems to be running on this port." );
  log_message( port:port, data:"A ActiveMQ JMS service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  00 3A 2D 45 52 52 20 45 72 72 6F 72 20 72 65 61    .:-ERR Error rea
# 0x10:  64 69 6E 67 20 66 72 6F 6D 20 73 6F 63 6B 65 74    ding from socket
# 0x20:  3A 20 55 6E 6B 6E 6F 77 6E 20 70 72 6F 74 6F 63    : Unknown protoc
# 0x30:  6F 6C 20 65 78 63 65 70 74 69 6F 6E 00 00          ol exception..
#
# Weblogic 12.3 NodeManager
# nb: Using only the default port 5556 as the pattern looks too generic
# and might match against other Java based products.
if( port == 5556 && ":-ERR Error reading from socket: Unknown protocol exception" >< r ) {
  service_register( port:port, proto:"nodemanager", message:"A Weblogic NodeManager service seems to be running on this port." );
  log_message( port:port, data:"A Weblogic NodeManager service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  04 20 4E 73 75 72 65 20 41 75 64 69 74 20 4C 69    . Nsure Audit Li
# 0x10:  6E 75 78 20 5B 37 66 35 31 32 32 30 32 3A 31 5D    nux [7f512202:1]
# 0x20:  0D 0A                                           ..
# Running on 1289/tcp
if( r =~ "Nsure Audit .* \[.*\]" ) {
  service_register( port:port, proto:"naudit", message:"A Novell Audit Secure Logging Server service seems to be running on this port." );
  log_message( port:port, data:"A Novell Audit Secure Logging Server service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  45 52 52 4F 52 0D 0A 45 52 52 4F 52 0D 0A 45 52    ERROR..ERROR..ER
# 0x10:  52 4F 52 0D 0A                                     ROR..
if( r =~ '^ERROR\r\nERROR\r\nERROR\r\n$' ) {
  service_register( port:port, proto:"memcached", message:"A Memcached service seems to be running on this port." );
  log_message( port:port, data:"A Memcached service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  85 10 00 00 00 00 00 00 62 00 00 00 0A 00 5C 49    ........b.....\I
# 0x10:  6E 76 61 6C 69 64 20 6F 72 20 75 6E 73 75 70 70    nvalid or unsupp
# 0x20:  6F 72 74 65 64 20 70 72 6F 74 6F 63 6F 6C 20 76    orted protocol v
# 0x30:  65 72 73 69 6F 6E 20 28 37 31 29 3B 20 73 75 70    ersion (71); sup
# 0x40:  70 6F 72 74 65 64 20 76 65 72 73 69 6F 6E 73 20    ported versions
# 0x50:  61 72 65 20 28 33 2F 76 33 2C 20 34 2F 76 34 2C    are (3/v3, 4/v4,
# 0x60:  20 35 2F 76 35 2D 62 65 74 61 29                    5/v5-beta)
#
# 0x00:  82 00 00 00 00 00 00 30 00 00 00 0A 00 2A 49 6E    .......0.....*In
# 0x10:  76 61 6C 69 64 20 6F 72 20 75 6E 73 75 70 70 6F    valid or unsuppo
# 0x20:  72 74 65 64 20 70 72 6F 74 6F 63 6F 6C 20 76 65    rted protocol ve
# 0x30:  72 73 69 6F 6E 3A 20 34                            rsion: 4
if( egrep( string:r, pattern: "Invalid or unsupported protocol version:? (\()?[0-9]+(\))?" ) ) {
  service_register( port:port, proto:"cql", message:"A Cassandra Query Language (CQL) service seems to be running on this port." );
  log_message( port:port, data:"A Cassandra Query Language (CQL) service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  55 6E 6B 6E 6F 77 6E 20 6D 65 73 73 61 67 65       Unknown message
# https://www.eyelock.com/index.php/products/myris
# Reported via http://lists.wald.intevation.org/pipermail/openvas-plugins/2018-March/001372.html
# nb: Only checking the two ports mentioned in the mailing list post above as
# the message is quite too common to check on all ports
if( ( port == 8083 || port == 9099 ) && rhexstr == "556e6b6e6f776e206d657373616765" ) {
  service_register( port:port, proto:"myris", message:"A Myris service seems to be running on this port." );
  log_message( port:port, data:"A Myris service seems to be running on this port." );
  exit( 0 );
}

# nb: Keep in sync with find_service2.nasl.
# Daytime seems to be responding late or even not to the HELP
# request there so trying to detect it here.
if( ereg( pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$",
          string:r ) ||
    ereg( pattern:"^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string:r, icase:TRUE ) ||
    r =~ '^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$' ||
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$' ||
    ereg( pattern:"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string:r ) ||
    # MS flavor of daytime
    ereg(pattern:"^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string:r ) ||
    # e.g. 0:00:42 07.02.2018 or 14:07:03 16.01.2018
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[0-2])\\.(19|20)[0-9][0-9][ \t\r\n]*$' ) {
  service_register( port:port, proto:"daytime" );
  log_message( port:port, data:"Daytime is running on this port" );
  exit( 0 );
}

# On 623/tcp
# 0x00:  00 00 00 02 09 00 00 00 01 00 00 00 00 00 00 00    ................
# 0x10:  00                                                 .
if( rhexstr =~ "^0000000209000000010000000000000000$" ) {
  service_register( port:port, proto:"ipmi-rmcp", message:"A IPMI RMCP service seems to be running on this port." );
  log_message( port:port, data:"A IMPI RMCP service seems to be running on this port." );
  exit( 0 );
}

# On 2701/tcp
# SCCM Remote Control (control), https://docs.microsoft.com/en-us/sccm/core/plan-design/hierarchy/ports
# Reported via http://lists.wald.intevation.org/pipermail/openvas-plugins/2018-April/001378.html
# 0x00:  22 00 00 80 20 00 53 00 54 00 41 00 52 00 54 00    "... .S.T.A.R.T.
# 0x10:  5F 00 48 00 41 00 4E 00 44 00 53 00 48 00 41 00    _.H.A.N.D.S.H.A.
# 0x20:  4B 00 45 00 00 00                                  K.E...
if( rhexstr =~ "^220000802000530054004100520054005F00480041004E0044005300480041004B0045000000" ) {
  service_register( port:port, proto:"sccm-control", message:"A SCCM Remote Control (control) service seems to be running on this port." );
  log_message( port:port, data:"A SCCM Remote Control (control) service seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^root@metasploitable:/# " ) {
  service_register( port:port, proto:"rootshell", message:"A root shell of Metasploitable seems to be running on this port." );
  log_message( port:port, data:"A root shell of Metasploitable seems to be running on this port." );
  exit( 0 );
}

# pfstatd on 9999/tcp
# 0x0000:  2D 31 20 2D 20 30 20 30 0A 30 20 2D 20 30 20 30    -1 - 0 0.0 - 0 0
# 0x0010:  0A 30 20 2D 20 31 20 30 0A 30 20 2D 20 32 20 30    .0 - 1 0.0 - 2 0
# 0x0020:  0A 30 20 2D 20 33 20 30 0A 30 20 2D 20 34 20 30    .0 - 3 0.0 - 4 0
# 0x0030:  0A 30 20 2D 20 35 20 30 0A 30 20 2D 20 36 20 30    .0 - 5 0.0 - 6 0
# 0x0040:  0A 30 20 2D 20 37 20 30 0A 30 20 2D 20 38 20 30    .0 - 7 0.0 - 8 0
# 0x0050:  0A 30 20 2D 20 39 20 30 0A 30 20 2D 20 31 30 20    .0 - 9 0.0 - 10
# 0x0060:  30 0A 30 20 2D 20 31 31 20 30 0A 30 20 2D 20 31    0.0 - 11 0.0 - 1
# 0x0070:  32 20 30 0A 30 20 2D 20 31 33 20 30 0A 30 20 2D    2 0.0 - 13 0.0 -
# 0x0080:  20 31 34 20 30 0A 30 20 2D 20 31 35 20 30 0A 30     14 0.0 - 15 0.0
# 0x0090:  20 2D 20 31 36 20 30 0A 30 20 2D 20 31 37 20 30     - 16 0.0 - 17 0
# 0x00A0:  0A 30 20 2D 20 31 38 20 30 0A 30 20 2D 20 31 39    .0 - 18 0.0 - 19
# 0x00B0:  20 30 0A 30 20 2D 20 32 30 20 30 0A 31 20 61 6C     0.0 - 20 0.1 al
# 0x00C0:  6C 20 30 20 30 0A 31 20 61 6C 6C 20 31 20 30 0A    l 0 0.1 all 1 0.
if( egrep( string:r, pattern:"^[0-9]+ (all|carp|em0|enc|enc0|lo|lo0|pflog0|pflog|\-) [0-9]+ [0-9]+$" ) ) {
  service_register( port:port, proto:"pfstatd", message:"A pfstatd service seems to be running on this port." );
  log_message( port:port, data:"A pfstatd service seems to be running on this port." );
  exit( 0 );
}

# R1Soft backup system on, http://wiki.r1soft.com/display/ServerBackup/Configure+network+ports
#
# Reported via http://lists.wald.intevation.org/pipermail/openvas-plugins/2018-May/001393.html
# 1167/tcp:
# 0x0000:  00 00 01 2E 52 AB 02 0A 14 08 A3 80 04 10 01 18    ....R...........
# 0x0010:  00 20 00 2A 08 4E 4F 54 46 4F 55 4E 44 10 00 1A    . .*.NOTFOUND...
# 0x0020:  90 02 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 55 42    ..-----BEGIN PUB
# 0x0030:  4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D 0A 4D 49 47    LIC KEY-----.MIG
# 0x0040:  66 4D 41 30 47 43 53 71 47 53 49 62 33 44 51 45    fMA0GCSqGSIb3DQE
# 0x0050:  42 41 51 55 41 41 34 47 4E 41 44 43 42 69 51 4B    BAQUAA4GNADCBiQK
# 0x0060:  42 67 51 44 32 78 57 72 31 58 64 5A 36 45 69 76    BgQD2xWr1XdZ6Eiv
#
# Alternatives found on the net on port 8000/tcp:
#
# 0x0000:  00 00 01 2E 52 AB 02 0A 14 08 A3 80 04 10 02 18    ....R...........
# 0x0010:  00 20 00 2A 08 4E 4F 54 46 4F 55 4E 44 10 00 1A    . .*.NOTFOUND...
# 0x0020:  90 02 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 55 42    ..-----BEGIN PUB
# 0x0030:  4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D 0A 4D 49 47    LIC KEY-----.MIG
# 0x0040:  66 4D 41 30 47 43 53 71 47 53 49 62 33 44 51 45    fMA0GCSqGSIb3DQE
# 0x0050:  42 41 51 55 41 41 34 47 4E 41 44 43 42 69 51 4B    BAQUAA4GNADCBiQK
# 0x0060:  42 67 51 44 48 4D 54 4E 6E 51 31 44 2F 78 74 79    BgQDHMTNnQ1D/xty
#
# or 8001/tcp:
# 0x0000:  00 00 01 32 52 AF 02 0A 18 08 A3 80 04 10 02 18    ...2R...........
# 0x0010:  00 20 01 2A 0C 56 4D 77 61 72 65 56 4D 77 61 72    . .*.VMwareVMwar
# 0x0020:  65 10 00 1A 90 02 2D 2D 2D 2D 2D 42 45 47 49 4E    e.....-----BEGIN
# 0x0030:  20 50 55 42 4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D     PUBLIC KEY-----
# 0x0040:  0A 4D 49 47 66 4D 41 30 47 43 53 71 47 53 49 62    .MIGfMA0GCSqGSIb
# 0x0050:  33 44 51 45 42 41 51 55 41 41 34 47 4E 41 44 43    3DQEBAQUAA4GNADC
# 0x0060:  42 69 51 4B 42 67 51 43 70 7A 73 39 54 47 6A 66    BiQKBgQCpzs9TGjf
#
# or 88/tcp which are sharing parts with the original reported service.
#
# 0x0000:  00 00 01 32 52 AF 02 0A 18 08 A3 80 04 10 01 18    ...2R...........
# 0x0010:  00 20 01 2A 0C 56 4D 77 61 72 65 56 4D 77 61 72    . .*.VMwareVMwar
# 0x0020:  65 10 00 1A 90 02 2D 2D 2D 2D 2D 42 45 47 49 4E    e.....-----BEGIN
# 0x0030:  20 50 55 42 4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D     PUBLIC KEY-----
# 0x0040:  0A 4D 49 47 66 4D 41 30 47 43 53 71 47 53 49 62    .MIGfMA0GCSqGSIb
# 0x0050:  33 44 51 45 42 41 51 55 41 41 34 47 4E 41 44 43    3DQEBAQUAA4GNADC
# 0x0060:  42 69 51 4B 42 67 51 44 66 4D 68 41 36 75 50 63    BiQKBgQDfMhA6uPc
if( rhexstr =~ "^000001..52..020A..08A3800410..180020..2A.*10001A9002" && "-----BEGIN PUBLIC KEY-----" >< r && "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" >< r ) {
  service_register( port:port, proto:"r1soft_backupagent", message:"A R1Soft Backup Agent seems to be running on this port." );
  log_message( port:port, data:"A R1Soft Backup Agent seems to be running on this port." );
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
# done in find_service_spontaneous.nasl as well. Please keep both in sync.
if( ( r =~ "^RPY [0-9] [0-9]" && "Content-Type: application/" >< r ) ||
    ( "<profile uri=" >< r && "http://iana.org/beep/" >< r ) ||
    "Content-Type: application/beep" >< r ) {
  service_register( port:port, proto:"beep", message:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  exit( 0 );
}

# https://github.com/beanshell/beanshell/blob/master/src/main/resources/bsh/commands/server.bsh
# 0x00:  42 65 61 6E 53 68 65 6C 6C 20 32 2E 30 62 34 20    BeanShell 2.0b4
# 0x10:  2D 20 62 79 20 50 61 74 20 4E 69 65 6D 65 79 65    - by Pat Niemeye
# 0x20:  72 20 28 70 61 74 40 70 61 74 2E 6E 65 74 29 0A    r (pat@pat.net).
# 0x30:  62 73 68 20 25 20 2F 2F 20 45 72 72 6F 72 3A 20    bsh % // Error:
# 0x40:  50 61 72 73 65 72 20 45 72 72 6F 72 3A 20 49 6E    Parser Error: In
# 0x50:  20 66 69 6C 65 3A 20 3C 75 6E 6B 6E 6F 77 6E 3E     file: <unknown>
# 0x60:  20 45 6E 63 6F 75 6E 74 65 72 65 64 20 22 48 6F     Encountered "Ho
# 0x70:  73 74 22 20 61 74 20 6C 69 6E 65 20 32 2C 20 63    st" at line 2, c
# 0x80:  6F 6C 75 6D 6E 20 31 2E 0A 0A 62 73 68 20 25 20    olumn 1...bsh %
#
# nb: With and without the banner. Just to be sure...
if( r =~ "^bsh % " || r =~ "^BeanShell " || "- by Pat Niemeyer (pat@pat.net)" >< r ) {
  service_register( port:port, proto:"beanshell", message:"A BeanShell listener service seems to be running on this port." );
  log_message( port:port, data:"A BeanShell listener service seems to be running on this port." );
  set_kb_item( name:"beanshell_listener/detected", value:TRUE ); # nb: No default port. Key is used as mandatory_key().
  exit( 0 );
}

# Running on a Hama IR110 WiFi Radio on port 10003/tcp
# Response length is always 261 or 263 bytes...
# 0x0000:  77 30 32 35 36 41 8F F6 EE 52 63 48 15 DB 14 B1    w0256A...RcH....
# 0x0010:  92 B6 5D 67 58 D1 76 C4 0F 45 D8 82 73 81 A2 2F    ..]gX.v..E..s../
# 0x0020:  F7 FD 49 F7 1B FB 94 93 56 C4 A6 9D 4D D7 67 FF    ..I.....V...M.g.
# 0x0030:  16 69 40 39 97 3C 51 D7 91 BD 47 F2 08 C2 D3 0D    .i@9.<Q...G.....
# 0x0040:  25 3C 7C 5C 9A 9D 4C C0 3E 7A 4A D6 D8 52 B4 57    %<|\..L.>zJ..R.W
# 0x0050:  CF 48 DE 49 9A 58 6F BC 02 B5 E3 D3 AF 75 47 DA    .H.I.Xo......uG.
# 0x0060:  83 BF 64 A4 D4 8E 24 00 BD C6 86 6C 69 AE DA B4    ..d...$....li...
# 0x0070:  BE C7 00 A0 24 58 0D F1 04 59 22 3C 4C EF C6 51    ....$X...Y"<L..Q
# 0x0080:  0B 8B 1A 09 B6 DC 3F 2C 1C A8 5C A7 07 CD C3 05    ......?,..\.....
# 0x0090:  00 6B E1 59 4A 1F 53 04 74 26 BD 03 EB 8E 74 9F    .k.YJ.S.t&....t.
# 0x00A0:  8E 48 EF F7 95 B0 B6 28 A9 5E 10 EB 47 88 02 97    .H.....(.^..G...
# 0x00B0:  B3 20 11 65 B0 01 9F 14 7B 33 03 58 E3 D4 B1 C2    . .e....{3.X....
# 0x00C0:  25 41 7D 9A 6E B7 F2 98 78 90 51 FE 5C 32 42 EC    %A}.n...x.Q.\2B.
# 0x00D0:  8E FD AD 93 E7 51 9D 82 19 79 12 76 EA 91 B4 4F    .....Q...y.v...O
# 0x00E0:  48 52 1B BB E3 F8 C3 B9 3A 37 6C BB E0 3A 32 49    HR......:7l..:2I
# 0x00F0:  88 D9 25 79 D4 AB 05 72 C8 79 1A 6C 21 40 BF 7C    ..%y...r.y.l!@.|
# 0x0100:  11 68 2E DD 1C                                     .h...
#
# nb: Pattern is not that reliable so checking the length as well...
if( r =~ "^w0256" && ( r_len == 261 || r_len == 263 ) ) {
  service_register( port:port, proto:"wifiradio-unknown", message:"An unknown service related to a WiFi radio seems to be running on this port." );
  log_message( port:port, data:"An unknown service related to a WiFi radio seems to be running on this port." );
  exit( 0 );
}

# Unknown telnet service running on 23/tcp. The check is not that reliable so checking the port as well...
# 0x00:  43 6F 6E 6E 65 63 74 69 6F 6E 20 72 65 66 75 73    Connection refus
# 0x10:  65 64 0D 0A                                        ed..
if( port == 23 && rhexstr == "436f6e6e656374696f6e20726566757365640d0a" ) {
  service_register( port:port, proto:"telnet", message:"A telnet service rejecting the access of the scanner seems to be running on this port." );
  log_message( port:port, data:"A telnet service rejecting the access of the scanner seems to be running on this port." );
  exit( 0 );
}

# Found on the IceWarp Suite (but there might be more similar products). This is a SIP service
# which isn't responding to our SIP OPTIONS request of sip_detection_tcp.nasl and find_service5.nasl
# 0x00:  53 49 50 2F 32 2E 30 20 34 30 30 20 42 61 64 20    SIP/2.0 400 Bad
# 0x10:  52 65 71 75 65 73 74 0D 0A 55 73 65 72 2D 41 67    Request..User-Ag
# 0x20:  65 6E 74 3A 20 49 63 65 57 61 72 70 20 53 49 50    ent: IceWarp SIP
# 0x30:  20 31 31 2E 31 2E 32 2E 31 20 44 45 42 37 20 78     11.1.2.1 DEB7 x
# 0x40:  36 34 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67    64..Content-Leng
# 0x50:  74 68 3A 20 30 0D 0A 56 69 61 3A 20 3B 72 65 63    th: 0..Via: ;rec
# 0x60:  65 69 76 65 64 3D 31 39 32 2E 31 36 38 2E 31 2E    eived=192.168.1.
# 0x70:  31 30 3B 72 70 6F 72 74 3D 34 35 34 36 31 3B 74    10;rport=45461;t
# 0x80:  72 61 6E 73 70 6F 72 74 3D 54 43 50 0D 0A 48 6F    ransport=TCP..Ho
# 0x90:  73 74 3A 20 74 65 73 74 0D 0A 0D 0A                st: test....
#
# Another special case on e.g. a AVM FRITZ!Box
# 0x0000:  53 49 50 2F 32 2E 30 20 34 30 30 20 49 6C 6C 65    SIP/2.0 400 Ille
# 0x0010:  67 61 6C 20 72 65 71 75 65 73 74 20 6C 69 6E 65    gal request line
# 0x0020:  0D 0A 46 72 6F 6D 3A 20 3C 73 69 70 3A 6D 69 73    ..From: <sip:mis
# 0x0030:  73 69 6E 67 3E 0D 0A 54 6F 3A 20 3C 73 69 70 3A    sing>..To: <sip:
# 0x0040:  6D 69 73 73 69 6E 67 3E 3B 74 61 67 3D 62 61 64    missing>;tag=bad
# 0x0050:  72 65 71 75 65 73 74 0D 0A 55 73 65 72 2D 41 67    request..User-Ag
# 0x0060:  65 6E 74 3A 20 46 52 49 54 5A 21 4F 53 0D 0A 43    ent: FRITZ!OS..C
# 0x0070:  6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 30    ontent-Length: 0
# 0x0080:  0D 0A 0D 0A 53 49 50 2F 32 2E 30 20 34 30 30 20    ....
if( sip_verify_banner( data:r ) ) {
  service_register( port:port, proto:"sip", message:"A service supporting the SIP protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the SIP protocol seems to be running on this port." );
  exit( 0 );
}

# Citrix NetScaler Metric Exchange Protocol on 3011/tcp
# 0x00:  10 00 00 00 A5 A5 00 00 D4 00 60 01 00 00 00 00    ..........`.....
if( rhexstr == "10000000a5a50000d400600100000000" ) {
  service_register( port:port, proto:"mep", message:"A service supporting the Metric Exchange Protocol (MEP) seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Metric Exchange Protocol (MEP) seems to be running on this port." );
  exit( 0 );
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
  service_register( port:port, proto:"chargen", message:"A chargen service seems to be running on this port." );
  log_message( port:port, data:"A chargen service seems to be running on this port." );
  exit( 0 );
}

# Xrdp on 3389/tcp seems to be responding like this
# 0x00:  03 00 00 09 02 F0 80 21 80                         .......!.
if( rhexstr == "0300000902f0802180" ) {
  service_register( port:port, proto:"ms-wbt-server", message:"A service (e.x. Xrdp) supporting the Microsoft Remote Desktop Protocol (RDP) seems to be running on this port." );
  log_message( port:port, data:"A service (e.x. Xrdp) supporting the Microsoft Remote Desktop Protocol (RDP) seems to be running on this port." );
  set_kb_item( name:"rdp/" + port + "/isxrdp", value:TRUE ); # Later used in check_xrdp() of ms_rdp_detect.nasl to avoid an already done request.
  exit( 0 );
}

# Service related to Siemens Building Management Systems (MBC, MEC, PXCM)
# on port 5441/tcp. The returned text seems to be deployment specific so
# we need to update this if we see other similar deployments. Make sure
# to not add any pattern with sensitive information in here...
if( port == 5441 &&
    ( "HEATINGNODE" >< r || "COOLINGNODE" >< r ||
      "CTL FLOW MAX" >< r || "OCC FLOW" >< r ||
      "$paneldefault" >< r || "NEGATIVE" >< r ||
      "POSITIVE" >< r ) ) {
  service_register( port:port, proto:"siemens-bms", message:"A service related to Siemens Building Management Systems seems to be running on this port." );
  log_message( port:port, data:"A service related to Siemens Building Management Systems seems to be running on this port." );
  exit( 0 );
}

# OMAPI https://en.wikipedia.org/wiki/OMAPI
# 0x00:  00 00 00 64 00 00 00 18                            ...d....
if( rhexstr == "0000006400000018" ) {
  service_register( port:port, proto:"omapi", message:"A service supporting the Object Management Application Programming Interface (OMAPI) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Object Management Application Programming Interface (OMAPI) protocol seems to be running on this port." );
  exit( 0 );
}

# Comvault Complete Backup & Recovery v11 sp 9-12
# https://www.commvault.com/complete-backup
# 0x00:  00 00 10 03 09 00 01 03 09 00 00 00 00 00 FF E8    ................
# 0x10:  00 00 00 0C 00 01 00 04 00 00 00 02 00 00 00 00    ................
# 0x20:  00 00 00 02                                        ....
if( rhexstr == "0000100309000103090000000000ffe80000000c00010004000000020000000000000002" ) {
  service_register( port:port, proto:"comvault-complete-backup", message:"A Comvault Complete Backup & Recovery service seems to be running on this port." );
  log_message( port:port, data:"A Comvault Complete Backup & Recovery service seems to be running on this port." );
  exit( 0 );
}

# Digi AnywhereUSB/14
# https://www.digi.com/products/usb-and-serial-connectivity/usb-over-ip-hubs/anywhereusb
# 0x00:  FF 14 50 6F 72 74 20 69 73 20 6F 75 74 20 6F 66    ..Port is out of
# 0x10:  20 72 61 6E 67 65 00 FF 14 50 6F 72 74 20 69 73     range...Port is
# 0x20:  20 6F 75 74 20 6F 66 20 72 61 6E 67 65 00 FF 14     out of range...
# 0x30:  50 6F 72 74 20 69 73 20 6F 75 74 20 6F 66 20 72    Port is out of r
# 0x40:  61 6E 67 65 00 FF 14 50 6F 72 74 20 69 73 20 6F    ange...Port is o
# 0x50:  75 74 20 6F 66 20 72 61 6E 67 65 00 FF 14 50 6F    ut of range...Po
# 0x60:  72 74 20 69 73 20 6F 75 74 20 6F 66 20 72 61 6E    rt is out of ran
# 0x70:  67 65 00                                           ge.
if( rhexstr == "ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500" ) {
  service_register( port:port, proto:"digi-usb", message:"A Digi AnywhereUSB/14 service seems to be running on this port." );
  log_message( port:port, data:"A Digi AnywhereUSB/14 service seems to be running on this port." );
  exit( 0 );
}

# mariadb - galera cluster port on e.g. 4567/tcp
# 0x00:  24 00 00 02 43 9D 3A 7F 00 01 10 00 B3 B7 1E CD    $...C.:.........
# 0x10:  A6 E7 11 E8 B9 33 E6 E4 2B A3 C7 AF 29 9F 98 AD    .....3..+...)...
# 0x20:  A8 3B 11 E8 A6 2B 7F 47 06 68 BC B7                .;...+.G.h..
if( rhexstr == "24000002439d3a7f00011000b3b71ecda6e711e8b933e6e42ba3c7af299f98ada83b11e8a62b7f470668bcb7 " ) {
  service_register( port:port, proto:"digi-usb", message:"A MariaDB galera cluster service seems to be running on this port." );
  log_message( port:port, data:"A MariaDB galera cluster service seems to be running on this port." );
  exit( 0 );
}

# Various IRC servers, e.g.
# nb: $hostname/$ip are placeholders for the hostname/ip of the target system, * are no placeholders and received as such...
# :irc.$hostname NOTICE AUTH :*** Looking up your hostname...
# ERROR :Your host is trying to (re)connect too fast -- throttled.
# :unknown.host 451 GET :You have not registered
# :$hostname NOTICE IP_LOOKUP :*** Looking up your hostname...
# :irc.$hostname NOTICE * :*** Looking up your hostname...
# ERROR :Trying to reconnect too fast.
# ERROR :Closing Link: [$ip] (Throttled: Reconnecting too fast)
if( r =~ "^:.* NOTICE AUTH :\*\*\* Looking up your hostname" ||
    r =~ "^ERROR :Your host is trying to \(re\)connect too fast -- throttled\." ||
    r =~ "^:.* 451 GET :You have not registered" ||
    r =~ "^:.* NOTICE IP_LOOKUP :\*\*\* Looking up your hostname\.\.\." ||
    r =~ "^:.* NOTICE \* :\*\*\* Looking up your hostname\.\.\." ||
    r =~ "^ERROR :Trying to reconnect too fast." ||
    ( r =~ "^ERROR :Closing Link:" && "(Throttled: Reconnecting too fast)" >< r ) ) {
  service_register( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );
  log_message( port:port, data:"An IRC server seems to be running on this port." );
  exit( 0 );
}

# rsh on 514/tcp if there is something wrong with the name resolution on the target host.
# The "real" detection will happen in rsh.nasl as it won't response if working correctly...
# 0x00:  01 67 65 74 6E 61 6D 65 69 6E 66 6F 3A 20 54 65    .getnameinfo: Te
# 0x10:  6D 70 6F 72 61 72 79 20 66 61 69 6C 75 72 65 20    mporary failure # nb: Ending space...
# 0x20:  69 6E 20 6E 61 6D 65 20 72 65 73 6F 6C 75 74 69    in name resoluti
# 0x30:  6F 6E 0A                                           on.
if( port == 514 && "getnameinfo: Temporary failure in name resolution" >< r ) {
  service_register( port:port, proto:"rsh", message:"A rsh service seems to be running on this port." );
  log_message( port:port, data:"A rsh service seems to be running on this port." );
  exit( 0 );
}

# https://nmap.org/book/nping-man-echo-mode.html
# 0x00:  01 01 00 18 65 23 33 C8 5B FB 9A 3D 00 00 00 00    ....e#3.[..=....
# 0x10:  56 5A 7B BE DF CC B2 0D CF 2B 9E 79 ED D6 70 FE    VZ{......+.y..p.
# 0x20:  74 46 96 FF 72 3F 0B 68 F6 A1 D3 85 C1 BD 54 64    tF..r?.h......Td
# 0x30:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x40:  17 F9 B0 49 07 8F 33 55 F3 19 4F 1E F4 4A F0 46    ...I..3U..O..J.F
# 0x50:  1E 5E 68 55 D5 A4 45 5E FA 18 D7 72 66 D8 AE EA    .^hU..E^...rf...
#
# or:
#
# 0x00:  01 01 00 18 5E EB 28 9B 5B FB 9A 24 00 00 00 00    ....^.(.[..$....
# 0x10:  E6 18 A4 F8 8B E3 55 A6 72 BE 37 A7 7E 83 5A 54    ......U.r.7.~.ZT
# 0x20:  48 A1 D1 77 5C FE 50 B6 45 AA 31 AB 08 FB CC 5D    H..w\.P.E.1....]
# 0x30:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x40:  B3 8F 34 BD B6 A6 6A 6D 4F E5 2E 53 EB 0B DE AD    ..4...jmO..S....
# 0x50:  01 DF 28 BD F0 28 90 EF CE C2 08 3B 23 59 E6 61    ..(..(.....;#Y.a
if( rhexstr =~ "^01010018.{16}00000000.{64}0{32}.{64}$" ) {
  service_register( port:port, proto:"nping-echo", message:"An nping-echo server seems to be running on this port." );
  log_message( port:port, data:"An nping-echo server seems to be running on this port." );
  exit( 0 );
}

# 0x00:  39 39 46 46 31 42 03 01 39 39 39 39 46 46 31 42    99FF1B..9999FF1B
# 0x10:  03 01 39 39 39 39 46 46 31 42 03 01 39 39 39 39    ..9999FF1B..9999
# 0x20:  46 46 31 42 03 01 39 39 39 39 46 46 31 42 03 01    FF1B..9999FF1B..
# 0x30:  39 39 39 39 46 46 31 42 03 01 39 39 39 39 46 46    9999FF1B..9999FF
# 0x40:  31 42 03 01 39 39 39 39 46 46 31 42 03 01 39 39    1B..9999FF1B..99
# 0x50:  39 39 46 46 31 42 03 01 39 39 39 39 46 46 31 42    99FF1B..9999FF1B
# 0x60:  03
#
# or:
#
# 0x00:  01 39 39 39 39 46 46 31 42 03 01 39 39 39 39 46    .9999FF1B..9999F
# 0x10:  46 31 42 03 01 39 39 39 39 46 46 31 42 03 01 39    F1B..9999FF1B..9
# 0x20:  39 39 39 46 46 31 42 03 01 39 39 39 39 46 46 31    999FF1B..9999FF1
# 0x30:  42 03 01 39 39 39 39 46 46 31 42 03 01 39 39 39    B..9999FF1B..999
# 0x40:  39 46 46 31 42 03 01 39 39 39 39 46 46 31 42 03    9FF1B..9999FF1B.
# 0x50:  01 39 39 39 39 46 46 31 42 03 01 39 39 39 39 46    .9999FF1B..9999F
# 0x60:  46 31 42 03                                        F1B.
#
# nb: See find_service6.nasl as well
#
# nb: The last digit is the EXT char which defaults to 0x03 but can be changed on some devices according to the vendor documentation.
if( rhexstr =~ "013939393946463142.." ) {
  service_register( port:port, proto:"automated-tank-gauge", message:"A Automated Tank Gauge (ATG) service seems to be running on this port." );
  log_message( port:port, data:"A Automated Tank Gauge (ATG) service seems to be running on this port." );
  exit( 0 );
}

# on port 1050/tcp:
# 0x00:  46 69 6E 67 65 72 20 6F 6E 6C 69 6E 65 20 75 73    Finger online us
# 0x10:  65 72 20 6C 69 73 74 20 72 65 71 75 65 73 74 20    er list request # nb: space
# 0x20:  64 65 6E 69 65 64 2E 0D 0A 0A                      denied....
#
# on port 79/tcp:
# 0x00:  55 6E 61 62 6C 65 20 74 6F 20 66 69 6E 64 20 73    Unable to find s
# 0x10:  70 65 63 69 66 69 65 64 20 75 73 65 72 2E 0D 0A    pecified user...
#
# 0x00:  4C 6F 67 69 6E 20 6E 61 6D 65 3A 20 47 45 54 20    Login name: GET # nb: space
# 0x10:  20 20 20 20 20 20 09 09 09 49 6E 20 72 65 61 6C          ...In real
# 0x20:  20 6C 69 66 65 3A 20 3F 3F 3F 0D 0A                 life: ???..
#
# nb: This example below is shorter because private IP/hostnames were removed.
# 0x0000:  0D 0A 20 20 20 20 4C 69 6E 65 20 20 20 20 20 55    ..    Line     U
# 0x0010:  73 65 72 20 20 20 20 20 20 48 6F 73 74 28 73 29    ser      Host(s)
# 0x0020:  20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20                    # nb: spaces
# 0x0030:  20 20 49 64 6C 65 20 4C 6F 63 61 74 69 6F 6E 0D      Idle Location.
# 0x0040:  0A 20 20 33 32 20 76 74 79 20 30 20 20 20 20 20    .  32 vty 0     # nb: spaces
# 0x0050:  20 20 20 20 20 20 20 20 69 64 6C 65 20 20 20 20            idle    # nb: spaces
# 0x0060:  20 20 20 20 20 20 20 20 20 20 20 20 20 30 30 3A                 00:
# 0x0070:  30 30 3A 30 31 20 31 35 34 2E 31 31 37 2E 31 35    00:01
if( r == 'Finger online user list request denied.\r\n\n' ||
    r == 'Unable to find specified user.\r\n' ||
    egrep( string:r, pattern:"Line\s+User\s+Host", icase:TRUE ) ||
    egrep( string:r, pattern:"Login\s+Name\s+TTY", icase:TRUE ) ||
    eregmatch( string:r, pattern:"^Login name: GET", icase:FALSE ) ) {
  service_register( port:port, proto:"finger", message:"A finger service seems to be running on this port." );
  log_message( port:port, data:"A finger service seems to be running on this port." );
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
# See find_service2.nasl as well
if( "Integrated port" >< r && "Printer Type" >< r && "Print Job Status" >< r ) {
  service_register( port:port, proto:"fingerd-printer", message:"A printer related finger service seems to be running on this port." );
  log_message( port:port, data:"A printer related finger service seems to be running on this port." );
  set_kb_item( name:"fingerd-printer/" + port + "/banner", value:ereg_replace( string:r, pattern:'(^\r\n|\r\n$)', replace:"" ) );
  exit( 0 );
}

# DICOM on 104/tcp and 11112/tcp
# nb: This is the A-ABORT message but not all services / implementations are responding to our probes.
#
# 0x00:  07 00 00 00 00 04 00 00 02 01                      ..........
#
# or (which seems to send different A-ABORT messages multiple times.
#
# 0x00:  07 00 00 00 00 04 00 00 00 00 07 00 00 00 00 04    ................
# 0x10:  00 00 02 02 07 00 00 00 00 04 00 00 02 02 07 00    ................
# 0x20:  00 00 00 04 00 00 02 02 07 00 00 00 00 04 00 00    ................
# 0x30:  02 02 07 00 00 00 00 04 00 00 02 02 07 00 00 00    ................
# 0x40:  00 04 00 00 02 02 07 00 00 00 00 04 00 00 02 02    ................
# 0x50:  07 00 00 00 00 04 00 00 02 02 07 00 00 00 00 04    ................
# 0x60:  00 00 02 02 07 00 00 00 00 04 00 00 02 02 07 00    ................
# 0x70:  00 00 00 04 00 00 02 02 07 00 00 00 00 04 00 00    ................
# 0x80:  02 02 07 00 00 00 00 04 00 00 02 02 07 00 00 00    ................
# 0x90:  00 04 00 00 02 02 07 00 00 00 00 04 00 00 02 02    ................
# 0xA0:  07 00 00 00 00 04 00 00 02 02 07 00 00 00 00 04    ................
# 0xB0:  00 00 02 02 07 00 00 00 00 04 00 00 02 02          ..............

if( rhexstr =~ "^(07000000000400000[0-2]0[0-6]){1,}$" ) {
  service_register( port:port, proto:"dicom", message:"A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
  log_message( port:port, data:"A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  4A 44 57 50 2D 48 61 6E 64 73 68 61 6B 65          JDWP-Handshake
if( r == "JDWP-Handshake" ) {
  service_register( port:port, proto:"jdwp", message:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  log_message( port:port, data:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  exit( 0 );
}

# nb: The same pattern is also checked in gb_rsync_remote_detect.nasl and find_service2.nasl.
# Please update those when updating the pattern here.
if( r =~ "^@RSYNCD: [0-9.]+" || r =~ "^You are not welcome to use rsync from " || r =~ "^rsync: (link_stat |error |.+unknown option)" ||
    r =~ "rsync error: (syntax or usage error|some files/attrs were not transferred) " || r =~ "rsync\s+version [0-9.]+\s+protocol version [0-9.]+" ) {
  service_register( port:port, proto:"rsync", message:"A service supporting the rsync protocol is running at this port." );
  log_message( port:port, data:"A service supporting the rsync protocol is running at this port." );
  exit( 0 );
}

# 0x00:  56 69 73 69 6F 6E 73 6F 66 74 20 41 75 64 69 74    Visionsoft Audit
# 0x10:  20 6F 6E 20 44 65 6D 61 6E 64 20 53 65 72 76 69     on Demand Servi
# 0x20:  63 65 0D 0A 56 65 72 73 69 6F 6E 3A 20 31 39 30    ce..Version: 190
# 0x30:  37 0D 0A 0D 0A 0A                                  7.....
# or:
#
# Visionsoft Audit on Demand Service
# Version: 303121750
if( "Visionsoft Audit on Demand Service" >< r ) {
  service_register( port:port, proto:"visionsoft-audit", message:"A Visionsoft Audit on Demand Service is running at this port." );
  log_message( port:port, data:"A Visionsoft Audit on Demand Service is running at this port." );
  exit( 0 );
}

# 0x00:  4F 4B 20 57 6F 72 6B 67 72 6F 75 70 53 68 61 72    OK WorkgroupShar
# 0x10:  65 20 32 2E 33 20 73 65 72 76 65 72 20 72 65 61    e 2.3 server rea
# 0x20:  64 79 0D 0A 45 52 52 4F 52 20 43 6F 6D 6D 61 6E    dy..ERROR Comman
# 0x30:  64 20 6E 6F 74 20 72 65 63 6F 67 6E 69 73 65 64    d not recognised
# 0x40:  0D 0A 45 52 52 4F 52 20 43 6F 6D 6D 61 6E 64 20    ..ERROR Command  # nb: space
# 0x50:  6E 6F 74 20 72 65 63 6F 67 6E 69 73 65 64 0D 0A    not recognised..
# 0x60:  45 52 52 4F 52 20 43 6F 6D 6D 61 6E 64 20 6E 6F    ERROR Command no
# 0x70:  74 20 72 65 63 6F 67 6E 69 73 65 64 0D 0A          t recognised..
#
# nb: See find_service_spontaneous.nasl as well
if( egrep( pattern:"^OK WorkgroupShare.+server ready", string:r, icase:FALSE ) ) {
  service_register( port:port, proto:"workgroupshare", message:"A WorkgroupShare Server is running at this port." );
  replace_kb_item( name:"workgroupshare/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"A WorkgroupShare Server is running at this port." );
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
# nb: See find_service2.nasl as well and keep the pattern on both the same.
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

# <?xml version="1.0" encoding="us-ascii"?>
# <junoscript xmlns="http://xml.juniper.net/xnm/1.1/xnm" xmlns:junos="http://xml.juniper.net/junos/15.1X49/junos" schemaLocation="http://xml.juniper.net/junos/15.1X49/junos junos/15.1X49/junos.xsd" os="JUNOS" release="15.1X49-D45" hostname="test" version="1.0">
# ...
if( r =~ '^<\\?xml version="1\\.0" encoding="us-ascii"\\?>[^<]+<junoscript xmlns="http://xml\\.juniper\\.net' ) {
  service_register( port:port, proto:"junoscript", message:"Juniper Junos OS JUNOScript seems to be running on this port" );
  replace_kb_item( name:"juniper/junos/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"Juniper Junos OS JUNOScript seems to be running on this port" );
  exit( 0 );
}

# Seen on FortiNAC port 1050/tcp but might be used similar on other products
#
# 0x0000:  AC ED 00 05 73 72 00 28 63 6F 6D 2E 62 73 63 2E    ....sr.(com.bsc.
# 0x0010:  61 70 69 2E 6C 6F 61 64 65 72 2E 5F 4C 6F 61 64    api.loader._Load
# 0x0020:  65 72 49 6E 74 65 72 66 61 63 65 5F 53 74 75 62    erInterface_Stub
# 0x0030:  B2 85 D2 C8 E0 44 5A 8B 02 00 00 78 72 00 14 6A    .....DZ....xr..j
# 0x0040:  61 76 61 78 2E 72 6D 69 2E 43 4F 52 42 41 2E 53    avax.rmi.CORBA.S
# 0x0050:  74 75 62 0F 18 8E 25 FB C0 10 1B 03 00 00 78 70    tub...%.......xp
# 0x0060:  77 B6 00 00 00 38 52 4D 49 3A 63 6F 6D 2E 62 73    w....8RMI:com.bs
# 0x0070:  63 2E 61 70 69 2E 6C 6F 61 64 65 72 2E 4C 6F 61    c.api.loader.Loa
# 0x0080:  64 65 72 49 6E 74 65 72 66 61 63 65 3A 30 30 30    derInterface:000
# 0x0090:  30 30 30 30 30 30 30 30 30 30 30 30 30 00 00 00    0000000000000...
# 0x00A0:  00 01 00 00 00 00 00 00 00 6E 00 01 02 00 00 00    .........n......
# 0x00B0:  00 0B 31 30 2E 39 37 2E 30 2E 31 35 00 00 AC CA    ..10.97.0.15....
# 0x00C0:  00 00 00 00 00 19 AF AB CB 00 00 00 00 02 CA 48    ...............H
# 0x00D0:  99 62 00 00 00 08 00 00 00 00 00 00 00 00 14 00    .b..............
# 0x00E0:  00 00 00 00 00 02 00 00 00 01 00 00 00 20 00 00    ............. ..
# 0x00F0:  00 00 00 01 00 01 00 00 00 02 05 01 00 01 00 01    ................
# 0x0100:  00 20 00 01 01 09 00 00 00 01 00 01 01 00 00 00    . ..............
# 0x0110:  00 26 00 00 00 02 00 02 78 75 72 00 02 5B 42 AC    .&......xur..[B.
# 0x0120:  F3 17 F8 06 08 54 E0 02 00 00 78 70 00 00 0C 66    .....T....xp...f
# 0x0130:  FE ED FE ED 00 00 00 02 00 00 00 02 00 00 00 02    ................
# 0x0140:  00 06 63 6C 69 65 6E 74 00 00 01 88 CA 47 6A C7    ..client.....Gj.
# 0x0150:  00 05 58 2E 35 30 39 00 00 03 8D 30 82 03 89 30    ..X.509....0...0
# 0x0160:  82 02 71 A0 03 02 01 02 02 04 40 CE 52 D5 30 0D    ..q.......@.R.0.
# 0x0170:  06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 30 75 31    ..*.H........0u1
# 0x0180:  0B 30 09 06 03 55 04 06 13 02 55 53 31 0B 30 09    .0...U....US1.0.
# 0x0190:  06 03 55 04 08 13 02 4E 48 31 10 30 0E 06 03 55    ..U....NH1.0...U
# 0x01A0:  04 07 13 07 43 6F 6E 63 6F 72 64 31 0C 30 0A 06    ....Concord1.0..
# 0x01B0:  03 55 04 0A 13 03 62 6E 69 31 1A 30 18 06 03 55    .U....bni1.0...U
# 0x01C0:  04 0B 13 11 42 72 61 64 66 6F 72 64 20 4E 65 74    ....Bradford Net
# 0x01D0:  77 6F 72 6B 73 31 1D 30 1B 06 03 55 04 03 13 14    works1.0...U....
# 0x01E0:  62 72 61 64 66 6F 72 64 6E 65 74 77 6F 72 6B 73    bradfordnetworks
# 0x01F0:  2E 63 6F 6D 30 1E 17 0D 32 31 30 35 30 35 31 32    .com0...21050512
# 0x0200:  34 33 35 34 5A 17 0D 33 31 30 35 30 33 31 32 34    4354Z..310503124
# 0x0210:  33 35 34 5A 30 75 31 0B 30 09 06 03 55 04 06 13    354Z0u1.0...U...
# 0x0220:  02 55 53 31 0B 30 09 06 03 55 04 08 13 02 4E 48    .US1.0...U....NH
# 0x0230:  31 10 30 0E 06 03 55 04 07 13 07 43 6F 6E 63 6F    1.0...U....Conco
# 0x0240:  72 64 31 0C 30 0A 06 03 55 04 0A 13 03 62 6E 69    rd1.0...U....bni
# 0x0250:  31 1A 30 18 06 03 55 04 0B 13 11 42 72 61 64 66    1.0...U....Bradf
# 0x0260:  6F 72 64 20 4E 65 74 77 6F 72 6B 73 31 1D 30 1B    ord Networks1.0.
# 0x0270:  06 03 55 04 03 13 14 62 72 61 64 66 6F 72 64 6E    ..U....bradfordn
# 0x0280:  65 74 77 6F 72 6B 73 2E 63 6F 6D 30 82 01 22 30    etworks.com0.."0
# 0x0290:  0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82    ...*.H..........
# 0x02A0:  01 0F 00 30 82 01 0A 02 82 01 01 00 89 77 CE B8    ...0.........w..
# 0x02B0:  46 FB 22 26 11 C4 B6 3F FE 12 7C 6A 28 E4 C2 CA    F."&...?..|j(...
# 0x02C0:  86 42 73 11 25 AA 44 FF A9 C3 A3 5C DE 0B 4C E5    .Bs.%.D....\..L.
# 0x02D0:  0B 16 D0 39 5C 33 BF AA 05 C3 BA 92 53 D9 7A A3    ...9\3......S.z.
# 0x02E0:  DF A4 8E 2E FE 46 53 47 4A E6 3D E2 87 53 F3 53    .....FSGJ.=..S.S
# 0x02F0:  45 D4 8E 73 05 D9 FA 2C 71 01 59 2D 99 0B 58 19    E..s...,q.Y-..X.
# 0x0300:  0D A9 BF BD A2 CD 65 49 9F 1D 65 EE D4 80 FD 99    ......eI..e.....
# 0x0310:  4D C8 03 AD 87 9B A9 65 0C 5A 23 24 FA 24 E9 22    M......e.Z#$.$."
# 0x0320:  A5 34 27 DE 6A 44 94 14 E8 4D 0C 9B FD 1E 41 4C    .4'.jD...M....AL
# 0x0330:  DE 62 A8 EE 91 14 9A B9 60 C7 45 F8 10 6A 21 B8    .b......`.E..j!.
# 0x0340:  1B E7 A4 06 D8 CA 5D 97 F4 89 1E 88 E3 92 30 4B    ......].......0K
# 0x0350:  61 D7 10 24 40 BF 59 A9 64 B6 12 83 9F 3E 1B 32    a..$@.Y.d....>.2
# 0x0360:  12 00 16 10 79 44 8A E6 A6 FA 72 05 A7 57 88 77    ....yD....r..W.w
# 0x0370:  29 3B F8 19 66 C4 F3 63 11 08 30 2E 78 C4 71 EA    );..f..c..0.x.q.
# 0x0380:  3B 5E 28 13 75 C9 43 49 4B 75 61 0C 82 D2 37 F6    ;^(.u.CIKua...7.
# 0x0390:  F0 8B 4B 37 BB 04 0E 41 35 8C C2 85 0B D2 CF E2    ..K7...A5.......
# 0x03A0:  6C D6 EC 4C 74 F9 FA 34 39 5B 57 0F 02 03 01 00    l..Lt..49[W.....
# 0x03B0:  01 A3 21 30 1F 30 1D 06 03 55 1D 0E 04 16 04 14    ..!0.0...U......
# 0x03C0:  A3 D9 C1 B1 31 72 F0 0C CC CA C9 3E 2A C1 FA E2    ....1r.....>*...
# 0x03D0:  AA CC 5F B8 30 0D 06 09 2A 86 48 86 F7 0D 01 01    .._.0...*.H.....
# 0x03E0:  0B 05 00 03 82 01 01 00 3A 41 7F FD 31 98 B9 63    ........:A..1..c
# 0x03F0:  38 A8 24 30 3E 07 5A 7C D4 2A CB 2E 48 AE D5 EE    8.$0>.Z|.*..H...
# 0x0400:  BA F5 A0 15 1C F0 FE D8 8D A3 17 18 A5 0B 36 7B    ..............6{
# 0x0410:  A3 96 39 92 BF C4 E0 19 0B 8F BF 49 31 34 A0 BB    ..9........I14..
# 0x0420:  DD B4 07 76 FE B1 27 68 9B 1B 19 E6 AF 52 63 F5    ...v..'h.....Rc.
# 0x0430:  DF C3 75 81 2B 8C 35 40 11 3A 4A 71 9E 1E E6 4E    ..u.+.5@.:Jq...N
# 0x0440:  77 A9 FD 5C 31 F9 65 36 CC EB 9B C9 23 37 3C 99    w..\1.e6....#7<.
# 0x0450:  14 BA 10 62 37 4F A6 B8 BB F2 08 5A 62 26 AF 7E    ...b7O.....Zb&.~
# 0x0460:  80 3B C8 D4 25 C4 69 EB C9 16 9F 59 0B E5 AF 4D    .;..%.i....Y...M
# 0x0470:  10 A9 EB C3 15 55 B1 69 77 BE 9B 41 8A CE EE CE    .....U.iw..A....
# 0x0480:  82 69 24 CB 47 CB EB 1A C1 D7 D5 15 D7 94 2C 83    .i$.G.........,.
# 0x0490:  EB 71 18 68 BE C3 81 C7 33 6A 60 C9 7D E7 86 E4    .q.h....3j`.}...
# 0x04A0:  70 66 C3 BF 4F C6 C8 47 AE 32 45 01 6B D1 15 F3    pf..O..G.2E.k...
# 0x04B0:  47 7D C6 EA 1B 89 FD F3 34 57 B1 3C 9B 15 FF 7F    G}......4W.<....
# 0x04C0:  B6 E3 1B 08 D8 A1 E4 08 E4 77 5C 22 00 24 C0 59    .........w\".$.Y
# 0x04D0:  18 40 E0 18 59 2B 3A F7 5C 50 67 9D 19 1A 00 A8    .@..Y+:.\Pg.....
# 0x04E0:  CF 6A 87 99 5B 3A 94 B0 00 00 00 01 00 06 73 65    .j..[:........se
# 0x04F0:  72 76 65 72 00 00 01 88 CA 47 6A C6 00 00 05 04    rver.....Gj.....
# 0x0500:  30 82 05 00 30 0E 06 0A 2B 06 01 04 01 2A 02 11    0...0...+....*..
# 0x0510:  01 01 05 00 04 82 04 EC 28 42 8B 8C 07 A7 89 40    ........(B.....@
# 0x0520:  59 C3 FB 8D 30 F3 28 3C 4B 4E 2A 41 E4 93 64 00    Y...0.(<KN*A..d.
# 0x0530:  7D CE 2E 81 19 1F C8 64 D8 AC 08 D1 21 88 DF 81    }......d....!...
# 0x0540:  D1 10 F2 AF 59 1A 61 57 40 15 EE 92 97 9F 9A 10    ....Y.aW@.......
# 0x0550:  7D E2 A9 71 C8 F3 99 F1 ED 92 EA BA 40 02 7E FE    }..q........@.~.
# 0x0560:  2D 5B E7 AD 88 5A 47 EB D7 22 1B 51 1A C5 7E E6    -[...ZG..".Q..~.
# 0x0570:  EA C0 01 8B 5D 23 73 1A 6F FE 61 CE 49 2E 63 08    ....]#s.o.a.I.c.
# 0x0580:  5D 90 41 37 A4 01 68 6B 35 48 CB 21 C5 11 61 AC    ].A7..hk5H.!..a.
# 0x0590:  DD 52 1E 66 63 1C 46 A1 E4 FD C3 AD BD 36 FD 15    .R.fc.F......6..
# 0x05A0:  35 4D D1 56 96 B6 0D 34 33 65 8A 7E 28 13 FF 6A    5M.V...43e.~(..j
# 0x05B0:  5F 18 70 63 CE 2E 8A 50 65 ED 51 EA E4 C3 F6 9C    _.pc...Pe.Q.....
# 0x05C0:  5A 8C 18 D7 54 D4 6B A7 7D 7B B0 F9 55 80 22 27    Z...T.k.}{..U."'
# 0x05D0:  F2 A3 98 A0 7C 86 73 01 C6 2B E9 48 C4 30 D9 EA    ....|.s..+.H.0..
# 0x05E0:  32 E4 EA 21 C5 4C 53 8F 9B 19 63 BD 49 BB D0 0F    2..!.LS...c.I...
# 0x05F0:  BF A1 DC F4 52 C0 38 57 F3 29 AB C2 58 4A A1 C2    ....R.8W.)..XJ..
# 0x0600:  DB 4B 47 53 FA 1F CC 6F 84 C4 BB B2 DB AC 2A B7    .KGS...o......*.
# 0x0610:  5C E2 44 C8 02 0D CF 40 84 B0 5E F5 C3 CB 06 3F    \.D....@..^....?
# 0x0620:  8D F2 98 2E 8E 30 95 08 44 F7 F3 E4 5B BF A0 20    .....0..D...[..
# 0x0630:  C6 32 77 A5 33 01 9B 4B AF FB A2 56 AA 94 3A 03    .2w.3..K...V..:.
# 0x0640:  BE 9D 5D B0 12 D1 49 5B EB 1D 1D DD AB C0 A6 43    ..]...I[.......C
# 0x0650:  4B D6 E3 0F B4 21 77 B3 D3 6F 9C 32 E0 68 53 8D    K....!w..o.2.hS.
# 0x0660:  25 3C 9F 70 5F A6 2B B2 1D 17 6D 6D 79 44 E3 27    %<.p_.+...mmyD.'
# 0x0670:  BC 81 E0 47 E4 E0 03 7A 02 20 6D B4 B0 A5 5A 67    ...G...z. m...Zg
# 0x0680:  59 25 82 F3 63 7A 71 F7 51 94 34 B9 61 B0 36 67    Y%..czq.Q.4.a.6g
# 0x0690:  82 72 C0 28 B9 75 6A D6 08 77 E7 38 AC B5 F5 4A    .r.(.uj..w.8...J
# 0x06A0:  DD 27 97 CB A6 D5 AE D0 33 AE 45 15 31 40 DE 72    .'......3.E.1@.r
# 0x06B0:  0B A5 3D 1F FF AC 6A C7 1E 4A 4A 84 6E 44 FF 6A    ..=...j..JJ.nD.j
# 0x06C0:  51 50 6C C2 55 25 8F 4D D8 9D 15 9C 45 79 78 C2    QPl.U%.M....Eyx.
# 0x06D0:  76 BD 59 09 5F 34 4B 91 21 91 C2 A7 FF 46 B1 A3    v.Y._4K.!....F..
# 0x06E0:  1B 8B 8B 69 2C AA CF 83 75 8E 46 BC 1C 45 53 67    ...i,...u.F..ESg
# 0x06F0:  D7 BC 4B BE DB 3C 7B 1E 80 F6 61 F4 39 34 77 F5    ..K..<{...a.94w.
# 0x0700:  26 B8 72 62 D1 94 6A 29 01 38 21 D7 5B 1A D5 EA    &.rb..j).8!.[...
# 0x0710:  29 3C BD 63 45 30 C9 38 16 FF 08 37 D0 06 27 63    )<.cE0.8...7..'c
# 0x0720:  D0 2D CC 14 9F 62 3D F9 BD 8F 98 49 75 CD 1F 94    .-...b=....Iu...
# 0x0730:  5E 01 0C 43 E9 18 B4 CE E7 D2 F2 39 83 22 E7 14    ^..C.......9."..
# 0x0740:  9D A4 72 CE 4C DC 75 2C 64 2F 53 7A 78 9C 48 53    ..r.L.u,d/Szx.HS
# 0x0750:  E8 5C 69 8B D5 DF B8 C5 26 99 25 B9 64 B9 E1 1F    .\i.....&.%.d...
# 0x0760:  C4 DD 6E 5C A5 16 B4 FE AF C9 52 84 93 69 CE AB    ..n\......R..i..
# 0x0770:  B8 0D 6B 2E 50 22 14 DB B4 AC 7F F7 AC B9 57 4F    ..k.P"........WO
# 0x0780:  05 4A 70 56 94 0A 0F 68 DF CA DC 36 AC 25 B6 D0    .JpV...h...6.%..
# 0x0790:  22 E4 EC 2F 8E 35 24 14 68 3D 86 1F B9 21 AC 35    "../.5$.h=...!.5
# 0x07A0:  1A 6E B8 4E BC ED 55 19 C8 0A 11 A3 27 F3 41 BE    .n.N..U.....'.A.
# 0x07B0:  8F CD BD 24 F4 D7 50 24 7E AC C1 7B 15 D7 92 2B    ...$..P$~..{...+
# 0x07C0:  9D 6E 62 99 59 81 08 B6 32 34 C8 31 AF B3 07 C9    .nb.Y...24.1....
# 0x07D0:  7C DE 06 1C 4D 11 3B 14 62 B0 0E 2C 38 A2 D9 81    |...M.;.b..,8...
# 0x07E0:  F7 12 CF 8B FE F7 42 EA A9 C6 F8 D8 45 D9 64 17    ......B.....E.d.
# 0x07F0:  E2 36 74 CF 9A 64 8B AB EE EF 5A F8 9B F5 98 12    .6t..d....Z.....
if( "javax.rmi.CORBA.Stub" >< rbinstr_space ) {
  service_register( port:port, proto:"corba", message:"A CORBA service seems to be running on this port." );
  log_message( port:port, data:"A CORBA service seems to be running on this port." );
  exit( 0 );
}

# On 9300/tcp
# 0x00:  54 68 69 73 20 69 73 20 6E 6F 74 20 61 20 48 54    This is not a HT
# 0x10:  54 50 20 70 6F 72 74                               TP port
# See find_service5.nasl as well
if( r =~ "^This is not a HTTP port$" ) {
  service_register( port:port, proto:"elasticsearch", message:"An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
  log_message( port:port, data:"An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
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
# nb: See find_service2.nasl and find_service3.nasl as well
if( rhexstr =~ "^5[19]000000$" ) {
  service_register( port:port, proto:"fw1-topology", message:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  log_message( port:port, data:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  exit( 0 );
}

# Some spontaneous banners are coming slowly, so they are wrongly registered as answers to GET
if( r =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$' ) {
  service_report( port:port, svc:"hddtemp" );
  exit( 0 );
}

# Some services are responding with an SSL/TLS alert we currently don't recognize
# e.g. 0x00:  15 03 01 00 02 02 0A                               .......
# or 0x00:  15 03 01                                           ...
# See also "Alert Protocol format" in http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
if( rhexstr =~ "^15030[0-3]00020[1-2]..$" ||
    rhexstr =~ "^1500000732$" || # nb: e.g. Novell Zenworks prebootserver on 998/tcp
    rhexstr =~ "^150301$" ) {
  service_register( port:port, proto:"ssl", message:"A service responding with an SSL/TLS alert seems to be running on this port." );
  log_message( port:port, data:"A service responding with an SSL/TLS alert seems to be running on this port." );
  exit( 0 );
}

# PowerFolder P2P data (usually on port 1337/tcp where bytes 3 and 4 differ).
# At least bytes 5 to 15 don't differ on several tested server responses.
#
# 0x00:  00 00 09 03 1F 8B 08 00 00 00 00 00 00 00 7D 97    ..............}.
# 0x10:  09 70 13 D7 19 C7 9F E4 4B F2 81 41 BE 0D 3E 68    .p......K..A..>h
# 0x20:  71 6A 48 22 63 0C 1E 1C 9A 4E 7C C8 58 46 B6 B1    qjH"c....N|.XF..
# 0x30:  25 5B 58 E6 C8 A2 7D 92 D6 5E ED 4A BB 6F 75 D0    %[X...}..^.J.ou.
# 0x40:  29 A5 34 21 2D 9D 81 99 86 49 5B 28 A1 D0 36 A5    ).4!-....I[(..6.
# 0x50:  E0 00 85 98 30 E9 91 66 20 84 D6 25 21 43 12 12    ....0..f ..%!C..
# 0x60:  92 80 87 94 04 48 42 52 B0 C9 C5 C4 7D DF 93 64    .....HBR....}..d
# 0x70:  6C 7A AC E7 ED BE DF 3B BE F7 BD FF F7 0E 79 F0    lz.....;......y.
if( rhexstr =~ "0000....1f8b08000000000000007d" ) {
  service_register( port:port, proto:"powerfolder_data", message:"A PowerFolder P2P data service is running at this port." );
  log_message( port:port, data:"A PowerFolder P2P data service is running at this port." );
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
# 0x0060:  00 31 00 31 00 39 00 35 00 37 00 32 00 35 00 38    .1.1.9.5.7.2.5.8
# 0x0070:  00 35 00 36 00 22 00 20 00 62 00 75 00 74 00 20    .5.6.". .b.u.t.  # nb: space
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
# 0x0160:  00 20 00 69 00 73 00 20 00 22 00 31 00 31 00 39    . .i.s. .".1.1.9
# 0x0170:  00 35 00 37 00 32 00 35 00 38 00 35 00 36 00 22    .5.7.2.5.8.5.6."
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
# 90047KVersion mismatch, driver version is "1195725856" but server version is "20"_org.h2.jdbc.JdbcSQLNonTransientConnectionException: Version mismatch, driver version is "1195725856" but server version is "20" [90047-204]at org.h2.message.DbException.getJdbcSQLException(DbException.java:697)at org.h2.message.DbException.getJdbcSQLException(DbException.java:496)at org.h2.message.DbException.get(DbException.java:227)at org.h2.server.TcpServerThread.run(TcpServerThread.java:107)at java.base/java.lang.Thread.run(Thread.java:829)
#
# nb: See find_service3.nasl as well, the different here is the "driver version" string above in
# the return because our different requests are interpreted as some kind of version.
if( rbinstr_nospace =~ "Version mismatch, driver version is.+but server version is.+org\.h2\.(jdbc|message|server)\." ) {
  service_register( port:port, proto:"h2", message:"A H2 Database service is running at this port." );
  log_message( port:port, data:"A H2 Database service is running at this port." );
  exit( 0 );
}

# nb:
# - Seen on port 1777/tcp
# - reporting from unknown_services.nasl / gb_unknown_os_service_reporting.nasl before this
#   detection got introduced
# - Similar pattern is used in find_service_spontaneous.nasl just to be sure to catch the services
#   at two places if it doesn't response to one probe (e.g. overloaded during "full" scans)
#
# Method: get_httpHex
#
# 0x0000:  00 00 01 60 00 00 00 25 00 00 01 2B 00 00 00 00    ...`...%...+....
# 0x0010:  00 00 00 02 00 00 00 05 00 00 00 01 68 2E 6D 69    ............h.mi
# 0x0020:  64 30 00 00 00 02 00 00 00 05 00 00 00 02 68 2E    d0............h.
# 0x0030:  63 6D 64 31 38 00 00 00 02 00 00 00 05 00 00 00    cmd18...........
# 0x0040:  03 70 2E 72 65 76 33 30 38 00 00 00 08 00 00 00    .p.rev308.......
# 0x0050:  06 00 00 00 1C 70 2E 67 75 69 64 30 30 35 30 35    .....p.guid00505
# 0x0060:  36 38 37 41 45 36 38 36 34 46 42 32 43 45 41 30    687AE6864FB2CEA0
# 0x0070:  30 30 30 30 30 32 46 00 00 00 02 00 00 00 09 00    000002F.........
# 0x0080:  00 00 01 70 2E 65 6E 63 72 79 70 74 30 00 00 00    ...p.encrypt0...
# 0x0090:  02 00 00 00 09 00 00 00 01 70 2E 65 6E 63 6D 65    .........p.encme
# 0x00A0:  74 68 30 00 00 00 06 00 00 00 04 00 00 00 12 70    th0............p
# 0x00B0:  2E 69 70 31 39 32 2E 31 36 38 2E 37 39 2E 34 3A    .ip192.168.79.4:
# 0x00C0:  34 37 36 36 33 00 00 00 01 00 00 00 05 00 00 00    47663...........
# 0x00D0:  05 70 2E 61 6D 63 36 2E 34 2E 30 00 00 00 09 00    .p.amc6.4.0.....
# 0x00E0:  00 00 09 00 00 00 0D 70 2E 65 6E 63 70 72 6F 74    .......p.encprot
# 0x00F0:  30 3B 30 3B 30 3B 30 3B 30 3B 30 3B 30 00 00 00    0;0;0;0;0;0;0...
# 0x0100:  07 00 00 00 05 00 00 00 0A 70 2E 6E 6F 77 31 36    .........p.now16
# 0x0110:  39 34 31 38 32 36 33 34 00 00 00 02 00 00 00 08    94182634........
# 0x0120:  00 00 00 05 70 2E 75 74 63 6F 66 66 32 35 32 30    ....p.utcoff2520
# 0x0130:  30 00 00 00 07 00 00 00 05 00 00 00 0A 70 2E 61    0............p.a
# 0x0140:  62 74 31 36 37 37 35 31 38 34 32 39 00 00 00 02    bt1677518429....
# 0x0150:  00 00 00 05 00 00 00 03 70 2E 70 63 66 34 36 33    ........p.pcf463
if( rhexstr =~ "702E67756964.+656E6370726F74.+7000000050000000a" ) {
  service_register( port:port, proto:"avalanche_mds", message:"An Ivanti Avalanche Mobile Device Server service seems to be running on this port." );
  log_message( port:port, data:"An Ivanti Avalanche Mobile Device Server service seems to be running on this port." );
  exit( 0 );
}

# Seen on e.g. port:
# - 9650/tcp (on OpenSearch docker containers)
# - 4690/tcp (on Render)
#
# e.g.:
#
# Method: get_httpHex
#
# 0x00:  00 00 12 04 00 00 00 00 00 00 03 7F FF FF FF 00    ................
# 0x10:  04 00 10 00 00 00 06 00 00 20 00 00 00 04 08 00    ......... ......
# 0x20:  00 00 00 00 00 0F 00 01 00 00 2B 07 00 00 00 00    ..........+.....
# 0x30:  00 00 00 00 00 00 00 00 01 55 6E 65 78 70 65 63    .........Unexpec
# 0x40:  74 65 64 20 48 54 54 50 2F 31 2E 78 20 72 65 71    ted HTTP/1.x req
# 0x50:  75 65 73 74 3A 20 47 45 54 20 2F 20                uest: GET / # nb: Trailing space

if( "Unexpected HTTP/1.x request: GET /" >< rbinstr_space ) {
  service_register( port:port, proto:"grpc", message:"A gRPC service seems to be running on this port." );
  log_message( port:port, data:"A gRPC service seems to be running on this port." );
  exit( 0 );
}

exit( 0 );

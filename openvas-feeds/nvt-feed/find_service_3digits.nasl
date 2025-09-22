# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14773");
  script_version("2023-06-14T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-06-14 05:05:19 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection (3 ASCII digit codes like FTP, SMTP, NNTP...)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl"); # cifs445.nasl
  script_require_ports("Services/three_digits");
  # "rpcinfo.nasl", "dcetest.nasl"

  script_xref(name:"URL", value:"https://forum.greenbone.net/c/vulnerability-tests/7");

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin is a complement of the plugin 'Services' (OID:
  1.3.6.1.4.1.25623.1.0.10330). It attempts to identify services that return 3 ASCII digit codes
  (ie: FTP, SMTP, NNTP, ...).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("port_service_func.inc");
include("misc_func.inc");

function read_answer( socket ) {

  local_var socket;
  local_var retry, i, r, answer;

  retry = 2;

  repeat {
    for( i = 0; i <= retry; i++ ) {
      r = recv_line( socket:socket, length:4096 );
      if( strlen( r ) > 0 )
        break;
    }
    answer += r;
  }
  until( ! r || r =~ '^[0-9]{3}[^-]' || strlen( answer ) > 1000000 );
  return answer;
}

if( ! port = get_kb_item( "Services/three_digits" ) )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

banner = read_answer( socket:soc );

if( banner )
  replace_kb_item( name:"FindService/tcp/" + port + "/spontaneous", value:banner );
else
  debug_print( "Banner is void on port ", port, "\n" );

# 500 = Unknown command
# 502 = Command not implemented

# If HELP works, it is simpler than anything else
send( socket:soc, data:'HELP\r\n' );
help = read_answer( socket:soc );
if( help ) {
  replace_kb_item( name:"FindService/tcp/" + port + "/help", value:help );
  if( ! banner )
    banner = help; # Not normal, but better than nothing
}

if( help && help !~ "^50[0-9]" ) {

  # See e.g. the following for a list of NNTP commands:
  # http://www.complang.tuwien.ac.at/tom/Projects/NewsCache/ThesisHTML/node54.html
  if( "ARTICLE" >< help || "NEWGROUPS" >< help || "NEWNEWS" >< help || "XHDR" >< help || "XOVER" >< help || banner =~ "^[0-9]{3} .*(NNTP|NNRP)" ) {
    service_report( port:port, svc:"nntp", banner:banner );
    close( soc );
    exit( 0 );
  }

  # nb: this must come before FTP recognition.
  if( egrep( string:banner, pattern:"^220.*HylaFAX .*Version.*" ) || egrep( string:help, pattern:"^220.*HylaFAX .*Version.*" ) ) {
    service_report( port:port, svc:"hylafax", banner:banner );
    close( soc );
    exit( 0 );
  }

  if( eregmatch( string:help, pattern:".*[a-z]{32}.*Authentication required\." ) ) {
    service_register( port:port, proto:"varnish-cli", message:"A Varnish control terminal seems to be running on this port." );
    log_message( port:port, data:"A Varnish control terminal seems to be running on this port." );
    close( soc );
    exit( 0 );
  }

  # iMQ Broker Rendezvous(imqbrokerd)
  # nb: this must come before FTP recognition.
  if( egrep( pattern:"^101", string:banner ) && ( egrep( pattern:"[a-zA-Z]+broker", string:banner, icase:TRUE ) ||
      egrep( pattern:"portmapper tcp PORTMAPPER", string:banner ) ) ) {
    service_register( port:port, proto:"imqbrokerd" );
    log_message( port:port, data:"A Message Queue broker is running at this port." );
    close( soc );
    exit( 0 );
  }

  # Code from find_service2.nasl
  if( help =~ "^220 .* SNPP " || egrep( string:help, pattern:"^214 .*PAGE" ) ) {
    service_report( port:port, svc:"snpp", banner:banner );
    close( soc );
    exit( 0 );
  }

  if( egrep( string:help, pattern:"^214-? " ) && "MDMFMT" >< help ) {
    service_report( port:port, svc:"hylafax-ftp", banner:banner );
    close( soc );
    exit( 0 );
  }

  # Code from find_service2.nasl:
  # SNPP, HylaFAX FTP, HylaFAX SPP, agobot.fo, IRC bots, WinSock server,
  # Note: this code must remain in find_service2.nasl until we think that
  # all find_service.nasl are up to date
  if( egrep( pattern:"^220 Bot Server", string:help ) ||
      raw_string( 0xb0, 0x3e, 0xc3, 0x77, 0x4d, 0x5a, 0x90 ) >< help ) {
    service_report( port:port, svc:"agobot.fo", banner:banner );
    close( soc );
    exit( 0 );
  }

  if( "220 WinSock" >< help ) { # or banner?
    service_report( port:port, svc:"winsock", banner:banner );
    close( soc );
    exit( 0 );
  }

  if( "PORT" >< help || "PASV" >< help ) {
    service_report( port:port, svc:"ftp", banner:banner );
    close( soc );
    exit( 0 );
  }
}

# e.g.:
# 220 HP GGW server (version 1.0) ready
# 220 JetDirect GGW server (version 1.0) ready
#
# nb: The same pattern is also used in all other find_service2.nasl to find_service6.nasl because
# there is always the slight chance that an overloaded target didn't responded to the initial
# service detection probes.
if( egrep( string:banner, pattern:"^220 (HP|JetDirect) GGW server \(version ([0-9.]+)\) ready" ) ) {
  service_register( port:port, proto:"hp-gsg", message:"A Generic Scan Gateway (GGW) server service is running at this port." );
  log_message( port:port, data:"A Generic Scan Gateway (GGW) server service is running at this port." );
  close( soc );
  exit( 0 );
}

# e.g.
# 554 No SMTPd here
# 554 No SMTP service here
# 554 No smtpd here
# 554-NO SMTP service
#
# nb: This is still a SMTP service which is blocking access according to:
# https://bobcares.com/blog/554-no-smtpd-here/
if( banner =~ "^554[ -]no smtpd? (service|here)" ) {
  service_register( port:port, proto:"smtp" );
  close( soc );
  exit( 0 );
}

# Unknown SMTP service
if( banner =~ "550[ -]Access denied \(not in relay or upstream list\)" ) {
  service_register( port:port, proto:"smtp" );
  close( soc );
  exit( 0 );
}

# nb: Should be outside of the "if" for the help status code above due to the "500" checked here.
if( "500 P-Error" >< help && "220 Hello" >< help ) { # or banner?
  service_report( port:port, svc:"unknown_irc_bot", banner:banner );
  close( soc );
  exit( 0 );
}

if( egrep( pattern:"^200 .* (PWD Server|poppassd)", string:banner ) ) {
  service_register( port:port, proto:"pop3pw" );
  close( soc );
  exit( 0 );
}

# e.g.:
# 220 8a3d01d704b5 LMTP Server (JAMES Protocols Server) ready
# 220 $hostname Zimbra LMTP server ready
# 220 2.1.5 LMTP server is ready
if( egrep( string:banner, pattern:"^220 [^ ]+( [^ ]+)? LMTP [Ss]erver.+ready", icase:FALSE ) ) {
  service_report( port:port, svc:"lmtp", banner:banner );
  close( soc );
  exit( 0 );
}

send( socket:soc, data:'HELO mail.example.org\r\n' );
helo = read_answer( socket:soc );

if( egrep( string:helo, pattern:"^250" ) ) {
  service_report( port:port, svc:"smtp", banner:banner );
  close( soc );
  exit( 0 );
}

# nb: Some systems might not include the "LMTP Server" banner above so we're sending a separate LHLO
# one as specified in https://datatracker.ietf.org/doc/html/rfc2033#section-4.1 to catch them.
send( socket:soc, data:'LHLO mail.example.org\r\n' );
lhlo = read_answer( socket:soc );

if( egrep( string:lhlo, pattern:"^250" ) ) {
  service_report( port:port, svc:"lmtp", banner:banner );
  close( soc );
  exit( 0 );
}

send( socket:soc, data:'DATE\r\n' );
date = read_answer( socket:soc );

if( date =~ '^111[ \t]+2[0-9]{3}[01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]' ) {
  service_report( port:port, svc:"nntp", banner:banner );
  close( soc );
  exit( 0 );
}

# nb: This should be kept at the bottom to first detect all services above before doing the more
# generic approach via the commands here which could cause some false detections.
ftp_commands = make_list( "CWD", "SYST", "PORT", "PASV" );
ko = 0;

foreach cmd( ftp_commands ) {

  send( socket:soc, data:cmd + '\r\n' );
  r = read_answer( socket:soc );

  if( ! r || egrep( string:r, pattern:"^50[0-9]" ) )
    ko++;
  debug_print( "Answer to ", cmd, ": ", r );

  if( cmd == "SYST" ) {
    # We store the result of SYST just in case. Most (>99%) FTP servers answer
    # "Unix Type: L8" so this is not very informative
    v = eregmatch( string:r, pattern:'^2[0-9][0-9] +(.*)[ \t\r\n]*$' );
    if( ! isnull( v ) )
      set_kb_item( name:"ftp/" + port + "/syst", value:v[1] );
  }
}

close( soc );

if( ! ko ) {
  service_report( port:port, svc:"ftp", banner:banner );
  exit( 0 );
}

if( substr( banner, 0, 3 ) == "200 " ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    vt_strings = get_vt_strings();
    banner = read_answer( socket:soc );
    send( socket:soc, data:string( "USER ", vt_strings["lowercase"], "\r\n" ) );
    r = read_answer( socket: soc );
    if( strlen( r ) > 3 && substr( r, 0, 3 ) == "200 " ) {
      send( socket:soc, data:string( "PASS ", vt_strings["lowercase_rand"], "\r\n" ) );
      r = read_answer( socket:soc );
      if( strlen( r ) > 3 && substr( r, 0, 3 ) == "500 " ) {
        service_register( port:port, proto:"pop3pw" );
        close( soc );
        exit( 0 );
      }
    }
    close( soc );
  }
}

# Give it to find_service2 & others
service_register( port:port, proto:"unknown" );
unknown_banner_set( port:port, banner:banner );

report  = 'Although this service answers with 3 digit ASCII codes like FTP, SMTP or NNTP servers, the Scanner was unable to identify it.\n\n';
report += 'This is highly suspicious and might be a backdoor; in this case, your system is compromised and an attacker can control it remotely.\n\n';
report += '** If you know what it is, consider this message as a false alert and please report it to the referenced community forum.\n\n';
report += 'Solution : disinfect or reinstall your operating system.';

log_message( port:port, data:report );
exit( 0 );

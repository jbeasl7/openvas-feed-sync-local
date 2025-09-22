# SPDX-FileCopyrightText: 2007 Javier Fernandez-Sanguino and Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Previously this was a single "cisco_default_pw.nasl" script which got split into
# "cisco_default_pw_ssh.nasl" and "cisco_default_pw_telnet.nasl" to have dedicated VTs for each
# protocol. The creation_date of both VTs have been kept on purpose.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.23938");
  script_version("2025-05-15T05:40:37+0000");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2007-11-04 00:32:20 +0100 (Sun, 04 Nov 2007)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cisco Device Default Credentials (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2007 Javier Fernandez-Sanguino and Renaud Deraison");
  script_family("CISCO");
  script_dependencies("telnetserver_detect_type_nd_version.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/cisco/ios/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete credentials list (not only vendor specific credentials)", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"The remote Cisco device has a default credentials set for the
  Telnet login.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via Telnet with known
  default credentials.");

  script_tag(name:"impact", value:"This allows an attacker to get a lot information about the
  network, and possibly to shut it down if the 'enable' password is not set either or is also a
  default password.");

  script_tag(name:"solution", value:"Change the default credentials immediately.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  # nb: Depending on the preference setting this VT might run for quite some time so choosing a
  # higher timeout here.
  script_timeout(900);

  exit(0);
}

include("default_account.inc");
include("default_credentials.inc");
include("dump.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

function check_cisco_account_telnet( port, login, password ) {

  local_var port, login, password;
  local_var banner, soc, msg, r, cmd, report;

  if( ! banner = telnet_get_banner( port:port ) )
    return 0;

  # nb: Check for banner, covers the case of Cisco telnet as well as the case of a console server to a Cisco port
  # Note: banners of cisco systems are not necessarily set, so this might lead to false negatives!
  if( stridx( banner, "User Access Verification" ) == -1 && stridx( banner, "assword:" ) == -1 )
    return 0;

  if( ! soc = open_sock_tcp( port ) )
    return 0;

  msg = telnet_negotiate( socket:soc, pattern:"(ogin:|asscode:|assword:)" );

  if( strlen( msg ) ) {

    # nb: The Cisco device might be using an AAA access model or have configured users.
    if( stridx( msg, "sername:" ) != -1 || stridx( msg, "ogin:" ) != -1 ) {
      send( socket:soc, data:string( login, "\r\n" ) );
      msg = recv_until( socket:soc, pattern:"(assword:|asscode:)" );
    }

    # nb: Device can answer back with {P,p}assword or {P,p}asscode if we don't get it then fail and close
    if( ! msg || ( stridx( msg, "assword:" ) == -1 && stridx( msg, "asscode:" ) == -1 ) ) {
      close( soc );
      return 0;
    }

    if( isnull( password ) )
      password = "";

    send( socket:soc, data:string( password, "\r\n" ) );
    recv( socket:soc, length: 4096 );

    # TBD: We could check for Cisco's prompt here, it is typically the device name followed by '>'.
    # But the actual regexp is quite complex, from Net-Telnet-Cisco:
    #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')

    # nb: Send a 'show ver', most users (regardless of privilege level) should be able to do this.
    cmd = "show ver";
    send( socket:soc, data:string( cmd, "\r\n" ) );

    # TBD: Both checks are probably not generic enough. Some Cisco devices don't use IOS but CatOS for example.
    r = recv_until( socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS) Software|assword:|asscode:|ogin:|% Bad password)" );

    if( "Cisco Internetwork Operating System Software" >< r || "Cisco IOS Software" >< r || r =~ "IOS(-| )X(E|R)" ) {
      if( login == "" )
        login = "empty/no username";
      if( password == "" )
        password = "empty/no password";
      report = 'It was possible to log in as \'' + login + '\'/\'' + password + '\'\n\n';
      report += 'Response to the "' + cmd + '" command (truncated):\n\n"' + substr( r, 0, 250 );
      security_message( port:port, data:report );
      close( soc );
      exit( 0 );
    }
  }

  close( soc );
  return 0;
}

port = telnet_get_port( default:23 );

check_cisco_account_telnet( port:port, login:"cisco", password:"cisco" );
check_cisco_account_telnet( port:port, login:"", password:"" );

p = script_get_preference( "Use complete credentials list (not only vendor specific credentials)", id:1 );
if( p && "yes" >< p )
  clist = default_credentials_get_list();
else
  clist = default_credentials_get_list( vendor:"cisco" ); # nb: Only get Cisco relevant credentials

if( ! clist )
  exit( 0 );

# nb: In an older version of this VT a call like the following existed here which exited early when
# save checks have been enabled:
#
# if( ! safe_checks() ) {
#
# It was unclear why this was included and it had been determined that this call was unnecessary so
# it was removed.
foreach credential( clist ) {

  # Handling of user uploaded credentials which requires to escape a ';' or ':'
  # in the user/password so it doesn't interfere with our splitting below.
  credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
  credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

  user_pass = split( credential, sep:":", keep:FALSE );
  if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) {
    # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
    # GSA is stripping ';' from the VT description. Keeping both in here
    # for backwards compatibility with older scan configs.
    user_pass = split( credential, sep:";", keep:FALSE );
    if( isnull( user_pass[0] ) || isnull( user_pass[1] ) )
      continue;
  }

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
  pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
  user = str_replace( string:user, find:"#sem_new#", replace:":" );
  pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

  if( tolower( user ) == "<<none>>" )
    user = "";

  if( tolower( pass ) == "<<none>>" )
    pass = "";

  # nb: Already checked initially so no need to test these...
  if( ( user == "cisco" && pass == "cisco" ) ||
      ( user == "" && pass == "" ) )
    continue;

  check_cisco_account_telnet( port:port, login:user, password:pass );
}

exit( 0 );

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
  script_oid("1.3.6.1.4.1.25623.1.0.104329");
  script_version("2025-05-15T05:40:37+0000");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2007-11-04 00:32:20 +0100 (Sun, 04 Nov 2007)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cisco Device Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2007 Javier Fernandez-Sanguino and Renaud Deraison");
  script_family("CISCO");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/cisco/ios/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete credentials list (not only vendor specific credentials)", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"The remote Cisco device has default credentials set for the SSH
  login.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via SSH with known default
  credentials.");

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

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("default_credentials.inc");
include("port_service_func.inc");
include("ssh_func.inc");

function check_cisco_account_ssh( port, login, password ) {

  local_var port, login, password;
  local_var soc, ret, cmd, r, report;

  if( ssh_dont_try_login( port:port ) )
    return 0;

  if( ! soc = open_sock_tcp( port ) )
    return 0;

  ret = ssh_login( socket:soc, login:login, password:password );
  if( ret == 0 ) {

    # TBD: We could check for Cisco's prompt here, it is typically the device name followed by '>'.
    # But the actual regexp is quite complex, from Net-Telnet-Cisco:
    #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')

    # Send a 'show ver', most users (regardless of privilege level) should be able to do this.
    cmd = "show ver";
    r = ssh_cmd( socket:soc, cmd:cmd, timeout:60, nosh:TRUE );
    close( soc );

    # TBD: This check is probably not generic enough. Some Cisco devices don't use IOS but CatOS for example.
    if( "Cisco Internetwork Operating System Software" >< r || "Cisco IOS Software" >< r || r =~ "IOS(-| )X(E|R)" ) {
      if( login == "" )
        login = "empty/no username";
      if( password == "" )
        password = "empty/no password";
      report = 'It was possible to log in as \'' + login + '\'/\'' + password + '\'\n\n';
      report += 'Response to the "' + cmd + '" command (truncated):\n\n"' + substr( r, 0, 250 );
      security_message( port:port, data:report );
      exit( 0 );
    }
  } else {
    close( soc );
    return 0;
  }
}

port = ssh_get_port( default:22 );

check_cisco_account_ssh( port:port, login:"cisco", password:"cisco" );
check_cisco_account_ssh( port:port, login:"", password:"" );

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

  check_cisco_account_ssh( port:port, login:user, password:pass );
}

exit( 0 );

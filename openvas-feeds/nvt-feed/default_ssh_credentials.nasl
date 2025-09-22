# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108013");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Brute Force Logins With Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_add_preference(name:"Seconds to wait between probes", value:"", type:"entry", id:1);

  script_timeout(900);

  script_tag(name:"summary", value:"A number of known default credentials are tried for the login
  via the SSH protocol.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the
  VT 'SSH Brute Force Logins With Default Credentials Reporting' (OID:
  1.3.6.1.4.1.25623.1.0.103239).");

  script_tag(name:"vuldetect", value:"Tries to login with a number of known default credentials via
  the SSH protocol.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_brute_force_checks" ) )
  exit( 0 );

include("default_credentials.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ssh_dont_try_login( port:port ) )
  exit( 0 );

# Exit if any random user/pass pair is accepted by the SSH service.
if( ssh_broken_random_login( port:port ) )
  exit( 0 );

# nb: From ssh_detect.nasl. This is only checking the supported authentication of an invalid user.
# However some SSH configs might allow passwords for specific users only with e.g. a "Match User"
# directive. To catch such configs we would need to bruteforce common users first.
ssh_supported_authentication = get_kb_item( "SSH/supportedauth/" + port );
if( ssh_supported_authentication && ssh_supported_authentication =~ "^publickey$" )
  exit( 0 );

c = 0;

d = script_get_preference( "Seconds to wait between probes", id:1 );
if( int( d ) > 0 )
  delay = int( d );

set_kb_item( name:"default_ssh_credentials/started", value:TRUE );

foreach credential( credentials ) {

  # Handling of user uploaded credentials which requires to escape a ';' or ':'
  # in the user/password so it doesn't interfere with our splitting below.
  credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
  credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

  user_pass_type = split( credential, sep:":", keep:FALSE );
  if( isnull( user_pass_type[0] ) || isnull( user_pass_type[1] ) ) {
    # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
    # GSA is stripping ';' from the VT description. Keeping both in here
    # for backwards compatibility with older scan configs.
    user_pass_type = split( credential, sep:";", keep:FALSE );
    if( isnull( user_pass_type[0] ) || isnull( user_pass_type[1] ) )
      continue;
  }

  # nb: Check the type of the credentials (defined in default_credentials.inc) if the credentials
  # should be tested by this VT
  type = user_pass_type[3];
  if( "all" >!< type && "ssh" >!< type )
    continue;

  # nb: Should be always after the type checks above as we only want to open the socket if we want
  # to check the credentials for this protocol.
  if( ! soc = open_sock_tcp( port ) )
    continue;

  user = chomp( user_pass_type[0] );
  pass = chomp( user_pass_type[1] );

  user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
  pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
  user = str_replace( string:user, find:"#sem_new#", replace:":" );
  pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

  if( tolower( user ) == "<<none>>" )
    user = "";

  if( tolower( pass ) == "<<none>>" )
    pass = "";

  login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );
  close( soc );

  if( login == '-2' )
    break; # "authentication succeeded using the none method". Against such SSH services it makes no sense to continue here

  if( login == 0 ) {
    c++;
    if( user == "" )
      user = "empty/no username";
    if( pass == "" )
      pass = "empty/no password";
    set_kb_item( name:"default_ssh_credentials/" + port + "/credentials", value:user + ":" + pass );

    if( c >= 10 ) {
      set_kb_item( name:"default_ssh_credentials/" + port + "/too_many_logins", value:c );
      break;
    }
  }

  if( delay ) {
    sleep( delay );
  } else {
    usleep( 50000 );
  }
}

exit( 0 );

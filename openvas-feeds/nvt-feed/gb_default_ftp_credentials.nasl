# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108717");
  script_version("2025-05-13T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2020-03-05 14:02:28 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FTP Brute Force Logins With Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_tag(name:"summary", value:"A number of weak/known credentials are tried for the login via
  the FTP protocol.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the
  VT 'FTP Brute Force Logins With Default Credentials Reporting' (OID:
  1.3.6.1.4.1.25623.1.0.108718).");

  script_tag(name:"vuldetect", value:"Tries to login with a number of weak/known credentials via the
  FTP protocol.");

  script_tag(name:"qod_type", value:"remote_active");

  script_timeout(900);

  exit(0);
}

if( get_kb_item( "default_credentials/disable_brute_force_checks" ) )
  exit( 0 );

include("default_credentials.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

# Exit if any random user/pass pair is accepted by the FTP service.
if( ftp_broken_random_login( port:port ) )
  exit( 0 );

c = 0;

set_kb_item( name:"default_ftp_credentials/started", value:TRUE );

foreach credential( credentials ) {

  # Handling of user uploaded credentials which requires to escape a ';' or ':' in the user/password
  # so it doesn't interfere with our splitting below.
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
  #
  # nb:
  # - "all" isn't used here as we don't want to run against all credentials from the
  #   default_credentials.inc
  # - To still support credentials uploaded by a user we need to use the "custom" vendor here as set
  #   by gb_default_credentials_options.nasl (default_credentials.inc) for such credentials
  type = user_pass_type[3];
  vendor = user_pass_type[2];
  if( "custom" >!< vendor && "ftp" >!< type )
    continue;

  # nb: Should be always after the type checks above as we only want to open the socket if we want
  # to check the credentials for this protocol.
  if( ! soc = ftp_open_socket( port:port ) )
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

  login = ftp_authenticate( socket:soc, user:user, pass:pass, skip_banner:TRUE );
  ftp_close( socket:soc );

  if( login ) {
    c++;
    if( user == "" )
      user = "empty/no username";
    if( pass == "" )
      pass = "empty/no password";
    set_kb_item( name:"default_ftp_credentials/" + port + "/credentials", value:user + ":" + pass );

    if( c >= 10 ) {
      set_kb_item( name:"default_ftp_credentials/" + port + "/too_many_logins", value:c );
      break;
    }
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2005 Charles Thier
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17638");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Avaya P330 Stackable Switch Default Credentials (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Charles Thier");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/avaya_p330/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete credentials list (not only vendor specific credentials)", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"The Avaya P330 stackable switch has default credentials set.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via Telnet with known
  default credentials.");

  script_tag(name:"impact", value:"The attacker could use these default credentials to gain remote
  access to the switch and then reconfigure the switch.

  These credentials could also be potentially used to gain sensitive information about the network
  from the switch.");

  script_tag(name:"solution", value:"Change the default credentials immediately.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");
include("default_credentials.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( ! banner || "Welcome to P330" >!< banner )
  exit( 0 );

p = script_get_preference( "Use complete credentials list (not only vendor specific credentials)", id:1 );
if( p && "yes" >< p )
  clist = default_credentials_get_list();
else
  clist = default_credentials_get_list( vendor:"avaya" );

if( ! clist )
  exit( 0 );

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

  # nb: Should be always after the type "validity" checks above as we only want to open the socket
  # if the credentials are well formatted.
  if( ! soc = open_sock_tcp( port ) )
    continue;

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

  answer = recv( socket:soc, length:4096 );
  if( "ogin:" >< answer ) {
    send( socket:soc, data:string( user, "\r\n" ) );
    answer = recv( socket:soc, length:4096 );
    send( socket:soc, data:string( pass, "\r\n" ) );
    answer = recv( socket:soc, length:4096 );

    if( "Password accepted" >< answer ) {
      if( user == "" )
        user = "empty/no username";
      if( pass == "" )
        pass = "empty/no password";
      security_message( port:port, data:"It was possible to login with the credentials '" + user + ":" + pass + "'." );
    }
  }
  close( soc );
}

exit( 0 );

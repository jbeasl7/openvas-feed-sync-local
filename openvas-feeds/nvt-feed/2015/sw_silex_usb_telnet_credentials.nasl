# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111054");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Silex USB-device Default Credentials (Telnet)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-13 15:00:00 +0100 (Fri, 13 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Silex USB-device Telnet has default credentials set.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of:

  - Username: root and an empty password or

  - Username: access and an empty password.");

  script_tag(name:"solution", value:"Change/Set the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

vuln = FALSE;
report = 'It was possible to login using the following credentials:';

port = telnet_get_port( default:23 );

users = make_list( "root", "access" );

foreach user( users ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  recv = recv( socket:soc, length:2048 );

  if( "silex" >!< recv ) {
    close( soc );
    exit( 0 );
  }

  if( "login:" >< recv ) {

    send( socket:soc, data:user +'\r\n' );
    recv = recv( socket:soc, length:128 );

    if( "needs password to login" >< recv ) {
      send( socket:soc, data:'\r\n' );
      recv = recv( socket:soc, length:1024 );
    }

    if( "User" >< recv && "logged in." >< recv ) {
      vuln = TRUE;
      report += "\n\n" + user + ":\n";
    }
  }
  close( soc );
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

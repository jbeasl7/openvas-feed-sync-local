# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112151");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Polycom HDX Default Credentials (Telnet)");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-08 09:24:56 +0100 (Fri, 08 Dec 2017)");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/polycom/device/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://staaldraad.github.io/2017/11/12/polycom-hdx-rce/");

  script_tag(name:"summary", value:"The Polycom device has default telnet credentials or passwordless login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to either gain direct access since no password is set or login with default credentials.");

  script_tag(name:"insight", value:"The Polycom series exposes an administrative console on port 23. This
  administrative interface is built on PSH (Polycom Shell) and allows management of
  the underlying device. By default there is no password, or the password is either
  set to 456, admin, or POLYCOM, there is no username.");

  script_tag(name:"solution", value:"It is recommended to disable the telnet access.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if ( "Polycom Command Shell" >< banner || "Welcome to ViewStation" >< banner || ( "Hi, my name is" >< banner && "Here is what I know about myself" >< banner ) ) {

  if ( "Polycom Command Shell" >< banner || ( "Hi, my name is" >< banner && "Here is what I know about myself" >< banner ) ) {

    soc = open_sock_tcp( port );
    if( ! soc ) exit( 0 );

    send( socket:soc, data: 'whoami\r\n' );
    recv = recv( socket:soc, length:2048 );
    close (soc);

    if ( "Hi, my name is" >< recv && "Here is what I know about myself" >< recv ) {
      VULN = TRUE;
      report = 'It was possible to gain access via telnet without entering any credentials.';
    }
  }

  if ( "Welcome to ViewStation" >< banner ) {
    report = 'It was possible to login via telnet using one or more of the following default credentials:\n';
    passwords = make_list( "456", "admin", "POLYCOM" );

    foreach pass ( passwords ) {
      soc = open_sock_tcp( port );
      if ( ! soc ) exit( 0 );

      recv = recv( socket:soc, length:2048 );

      if ( "Password" >< recv ) {
        send( socket:soc, data: pass + '\r\n' );
        recv = recv( socket:soc, length:1024 );

        if ( "Polycom Command Shell" >< recv ) {
          send( socket:soc, data: 'whoami\r\n' );
          recv = recv( socket:soc, length:2048 );

          if ( "Hi, my name is" >< recv && "Here is what I know about myself" >< recv ) {
            VULN = TRUE;
            report += '\nPassword: ' + pass;
          }
        }
      }
      close ( soc );
    }
  }

  if( VULN ) {
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

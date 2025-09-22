# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105492");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Adcon A840 Telemetry Gateway 'root' Default Credentials (Telnet)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-17 17:26:56 +0100 (Thu, 17 Dec 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_adcon_A840_telemetry_gateway_telnet_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("tg_A840/telnet/port");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:'The remote Adcon A840 Telemetry Gateway
  has default credentials set.');

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of root:840sw");

  script_tag(name:"solution", value:"Change/Set the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");

if( ! port = get_kb_item("tg_A840/telnet/port") ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = telnet_negotiate( socket:soc );

if( "a840 login:" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: 'root\r\n' );
sleep( 3 );
recv = recv( socket:soc, length:128 );

if( "Password:" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: '840sw\r\n' );
sleep(3);
recv = recv( socket:soc, length:1024 );

if( ( recv && ">" >< recv ) && "Login incorrect" >!< recv )
{
  send( socket:soc, data: 'uname -a\r\n' );
  recv = recv( socket:soc, length:128 );

  if( recv =~ '^Linux a840' )
  {
    security_message( port:port );
    close( soc );
    exit( 0 );
  }
}

if( soc ) close( soc );

exit( 99 );


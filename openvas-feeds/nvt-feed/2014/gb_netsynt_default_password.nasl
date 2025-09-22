# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103901");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Netsynt CRD Voice Router CLI Default Credentials (Telnet)");
  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/02/04/netsynt-crd-voice-router-telnet-cli-default-password/");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-06 15:02:06 +0200 (Thu, 06 Feb 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/netsynt/crd_voice_router/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Netsynt CRD Voice Router has a default password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default password.");

  script_tag(name:"insight", value:"It was possible to login using 'netsynt' as password.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default:23);
banner = telnet_get_banner(port:port);
if( ! banner || "Netsynt " >!< banner )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

recv = telnet_negotiate( socket:soc );
if( ! recv || ( "Netsynt " >!< recv && "Password:" >!< recv ) )
  exit( 0 );

send( socket:soc, data:'netsynt\n' );
send( socket:soc, data:'\n' );

recv = recv( socket:soc, length:2048 );
close( soc );

if( "Type Help to display the list of commands" >< recv )
{
  security_message( port:port );
  exit( 0 );
}

exit ( 99 );

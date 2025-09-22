# SPDX-FileCopyrightText: 2000 Stefaan Van Dooren
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10500");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Shiva Integrator Default Password (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2000 Stefaan Van Dooren");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Telnet to this router and set a different password immediately.");

  script_tag(name:"summary", value:"The remote Shiva router uses the default password.
  This means that anyone who has (downloaded) a user manual can
  telnet to it and reconfigure it to lock you out of it, and to
  prevent you to use your internet connection.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = telnet_get_port( default:23 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

data = string( "hello\n\r" );
send( data:data, socket:soc );
buf = recv( socket:soc, length:4096 );

close( soc );

if( "ntering privileged mode" >< buf ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

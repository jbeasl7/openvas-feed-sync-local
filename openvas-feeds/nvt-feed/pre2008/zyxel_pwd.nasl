# SPDX-FileCopyrightText: 2001 Giovanni Fiaschi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10714");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3161");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0571");
  script_name("Zyxel Router Default Credentials (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Giovanni Fiaschi");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports(23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Telnet to this router and set a password immediately.");

  script_tag(name:"summary", value:"The remote host is a Zyxel router with its default password set.");

  script_tag(name:"impact", value:"An attacker could telnet to it and reconfigure it to lock the owner out and to
  prevent him from using his Internet connection, or create a dial-in user to
  connect directly to the LAN attached to it.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

port = 23;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = recv( socket:soc, length:8192, min:1 );
if( "Password:" >!< r ) exit( 0 );

s = string( "1234\r\n" );
send( socket:soc, data:s );
r = recv( socket:soc, length:8192, min:1 );
close( soc );

if( "ZyXEL" >< r ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103726");
  script_version("2025-04-29T05:39:55+0000");
  script_name("Unprotected Windows CE Console (Telnet)");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-06-03 12:36:40 +0100 (Mon, 03 Jun 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  # nb: The sent command could be already seen as an attack
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");

  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login (at least currently)...
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"The remote Windows CE Telnet Console is not protected by a
  password.");

  script_tag(name:"vuldetect", value:"Checks if credentials are required to access the device.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Set a password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: Don't exit via islocalhost() or is_private_lan() here as such a system should be definitely
# access protected.

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = telnet_get_port( default:23 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

buf = telnet_negotiate( socket:soc );

if( ! buf || "Welcome to the Windows CE Telnet Service" >!< buf && "Pocket CMD" >!< buf && "\>" >!< buf ) {
  close( soc );
  exit( 0 );
}

send( socket:soc, data:'help\n' );
recv = recv( socket:soc, length:512 );

send( socket:soc, data:'exit\n' );
close( soc );

if( "The following commands are available:" >< recv && "DEL" >< recv ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

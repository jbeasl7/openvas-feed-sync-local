# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140133");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Default Password 'avam@r' for 'root' Account (SSH)");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-01-31 11:12:08 +0100 (Tue, 31 Jan 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote host has the password 'avam@r' for the root account.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: 'root/avam@r'.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("os_func.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ssh_dont_try_login( port:port ) )
  exit( 0 );

# nb: No need to continue/start if we haven't received any banner...
if( ! ssh_get_serverbanner( port:port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

user = "root";
pass = "avam@r";

login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  files = traversal_files( "linux" );

  foreach pattern( keys( files ) ) {

    file = "/" + files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat " + file, nosh:TRUE );

    if( egrep( string:cmd, pattern:pattern, icase:TRUE ) ) {
      if( soc ) close( soc );
      report = 'It was possible to login as user `root` with password `avam@r` and to execute `cat ' + file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

if( soc ) close( soc );
exit( 99 );

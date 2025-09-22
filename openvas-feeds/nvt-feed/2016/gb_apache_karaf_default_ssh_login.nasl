# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105593");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-04-01 15:59:09 +0200 (Fri, 01 Apr 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Apache Karaf Default Credentials (SSH)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 8101);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Apache Karaf is using known default credentials.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials:
  'karaf/karaf'.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("ssh_func.inc");

port = ssh_get_port( default:8101 );

if( ssh_dont_try_login( port:port ) )
  exit( 0 );

# nb: No need to continue/start if we haven't received any banner...
if( ! ssh_get_serverbanner( port:port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

user = "karaf";
pass = "karaf";

login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  files = traversal_files( "linux" );

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat /" + file, nosh:TRUE );

    if( egrep( string:cmd, pattern:pattern ) ) {
      if( soc )
        close( soc );
      report = 'It was possible to login as user `karaf` with password `karaf` and to execute `cat /' +
               file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

if( soc )
  close( soc );

exit( 99 );

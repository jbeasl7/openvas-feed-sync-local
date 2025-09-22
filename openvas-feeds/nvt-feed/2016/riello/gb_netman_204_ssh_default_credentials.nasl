# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140001");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Riello NetMan 204 Default Credentials (SSH)");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-09-28 15:56:01 +0200 (Wed, 28 Sep 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41208");

  script_tag(name:"summary", value:"The remote Riello NetMan 204 network card is using known default
  credentials for the SSH login.");

  script_tag(name:"vuldetect", value:"Tries to login using known default credentials.

  Note: The default 'admin' and 'user' credentials might be also reported for non-Riello devices.
  This result is currently expected.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password of the affected account(s).");

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

# nb:
# - eurek:eurek is from the exploit-db entry
# - Others are default credentials on the target according to the NetMan 204 manual
# - admin:admin and eurek:eurek are tested first as these are the "most" valuable ones
credentials = make_array(
  "admin", "admin",
  "eurek", "eurek",
  "fwupgrade", "fwupgrade",
  "user", "user" );

foreach username( keys( credentials ) ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  password = credentials[username];
  login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
  if( login == 0 ) {

    files = traversal_files( "linux" );

    foreach pattern( keys( files ) ) {

      file = files[pattern];

      cmd = ssh_cmd( socket:soc, cmd:"cat /" + file );

      if( egrep( string:cmd, pattern:pattern ) ) {
        report = "It was possible to login as user '" + username + "' with password '" + password + "' and to execute 'cat /" + file + "'. Result:" + '\n\n' + chomp( cmd );
        close( soc );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

if( soc ) close( soc );
exit( 99 );

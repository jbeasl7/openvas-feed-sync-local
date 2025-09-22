# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117305");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-04-12 06:07:57 +0000 (Mon, 12 Apr 2021)");
  script_name("VyOS Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/openssh/detected"); # nb: VyOS docs shows that the devices are running OpenSSH
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://support.vyos.io/en/kb/articles/default-user-password-for-vyos-2");

  script_tag(name:"summary", value:"The remote VyOS system is using known default credentials for
  the SSH login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'vyos:vyos'.");

  script_tag(name:"affected", value:"All VyOS systems using known default credentials.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("os_func.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ssh_dont_try_login( port:port ) )
  exit( 0 );

banner = ssh_get_serverbanner( port:port );
if( ! banner || banner !~ "OpenSSH" )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

username = "vyos";
password = "vyos";

login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  files = traversal_files( "linux" );

  foreach pattern( keys( files ) ) {

    file = "/" + files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat " + file );

    if( egrep( string:cmd, pattern:pattern, icase:TRUE ) ) {

      close( soc );

      report = 'It was possible to login to the remote VyOS system via SSH with the following known credentials:\n';
      report += '\nUsername: "' + username  + '", Password: "' + password + '"\n';
      report += 'and to execute `cat ' + file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

close( soc );

exit( 99 );

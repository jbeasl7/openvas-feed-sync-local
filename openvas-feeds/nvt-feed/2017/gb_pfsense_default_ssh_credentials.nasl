# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112123");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-11-15 13:32:16 +0100 (Wed, 15 Nov 2017)");
  script_name("pfSense Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"pfSense is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information
  or modify the system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with known credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.question-defense.com/2012/11/19/pfsense-default-login");
  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/HOWTO_enable_SSH_access");

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

password = "pfsense";
report = 'It was possible to login to pfSense via SSH with the following credentials:\n';

files = traversal_files( "linux" );

foreach username( make_list( "admin", "root" ) ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
  if( login == 0 ) {

    foreach pattern( keys( files ) ) {

      file = files[pattern];

      rcv = ssh_cmd( socket:soc, cmd:'8\n && cat /' + file, nosh:TRUE, pty:TRUE );

      if( 'Welcome to pfSense' >< rcv && egrep( string:rcv, pattern:pattern ) ) {
        vuln = TRUE;
        report += '\nUsername: "' + username  + '", Password: "' + password + '"';
      }

      if( passwd = egrep( pattern:pattern, string:rcv ) ) {
        passwd_report += '\nIt was also possible to execute "cat /' + file + '" as "' + username + '". Result:\n\n' + passwd;
      }
    }
  }
  close( soc );
}

if( vuln ) {
  if (passwd_report) report += '\n' + passwd_report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105278");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-05-12 18:01:07 +0200 (Tue, 12 May 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Citrix NetScaler Default Credentials (SSH)");

  script_category(ACT_ATTACK);

  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Citrix NetScaler system is using known default
  credentials for the SSH login.");

  script_tag(name:"vuldetect", value:"Tries to login using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ssh_dont_try_login( port:port ) )
  exit( 0 );

# nb: No need to continue/start if we haven't received any banner...
if( ! ssh_get_serverbanner( port:port ) )
  exit( 0 );

# nb:
# - This VT as well as the following:
#   2015/citrix/gb_netscaler_http_default_credentials.nasl
#   had only used "nsroot:nsroot" initially for HTTP and SSH. But external resources indicates that
#   this credentials pair is for HTTP while "nsroot:nsroot" is used for SSH. For possible increased
#   coverage we're just testing both here now to make sure to catch all possible variants.
# - "nsroot:nsroot" should be kept first
# - Some more info can be found e.g. here:
#   - https://msandbu.wordpress.com/2012/01/30/citrix-netscaler/
#   - https://docs.netscaler.com/en-us/netscaler-application-delivery-management-software/current-release/manage-system-settings/how-to-reset-password.html
creds = make_list(
  "nsroot:nsroot",
  "nsrecover:nsroot"
);

report = 'It was possible to successfully log in via SSH with the following known default credentials:\n';

foreach cred( creds ) {

  split = split( cred, sep:":", keep:FALSE );
  if( max_index( split ) != 2 )
    continue;

  if( ! soc = open_sock_tcp( port ) )
    continue;

  username = split[0];
  password = split[1];

  login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
  if( login == 0 ) {

    cmd = "show ns version";
    res = ssh_cmd( socket:soc, cmd:cmd, nosh:TRUE );

    if( "NetScaler" >< res ) {
      VULN = TRUE;
      report += '\nUsername: ' + username  + '\nPassword: ' + password + '\n\n';
      report += 'and to execute "' + cmd + '".\n\nResponse:\n\n' + chomp( res );
    }
  }

  close( soc );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

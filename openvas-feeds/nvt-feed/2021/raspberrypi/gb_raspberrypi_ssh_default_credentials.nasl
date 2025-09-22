# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117815");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2021-38759");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 14:17:00 +0000 (Fri, 10 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-09 07:53:21 +0000 (Thu, 09 Dec 2021)");
  script_name("Raspberry Pi OS / Raspbian Default Credentials (SSH)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl", "os_detection.nasl");
  script_require_ports("Services/ssh", 22);
  # nb: No other mandatory key for the SSH server itself as there might be different SSH servers
  # installed (OpenSSH, Dropbear, ...)
  script_mandatory_keys("Host/runs_unixoide");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.raspberrypi.com/documentation/computers/configuration.html#change-the-default-password");
  script_xref(name:"URL", value:"https://www.cnvd.org.cn/flaw/show/CNVD-2021-43968");

  script_tag(name:"summary", value:"The remote Raspberry Pi OS / Raspbian system is using known
  default credentials for the SSH login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'pi:raspberry'.");

  script_tag(name:"affected", value:"All Raspberry Pi OS / Raspbian systems using known default
  credentials. Other systems might be affected as well.");

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

# nb: No need to continue/start if we haven't received any banner...
if( ! ssh_get_serverbanner( port:port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

username = "pi";
password = "raspberry";

login = ssh_login( socket:soc, login:username, password:password, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  files = traversal_files( "linux" );

  foreach pattern( keys( files ) ) {

    file = "/" + files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:"cat " + file );

    if( egrep( string:cmd, pattern:pattern, icase:TRUE ) ) {

      close( soc );

      report = 'It was possible to login to the remote Raspberry Pi OS / Raspbian system via SSH with the following known credentials:\n';
      report += '\nUsername: "' + username  + '", Password: "' + password + '"\n';
      report += 'and to execute `cat ' + file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

close( soc );

exit( 99 );

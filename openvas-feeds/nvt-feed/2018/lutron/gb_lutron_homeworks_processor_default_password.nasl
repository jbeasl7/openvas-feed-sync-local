# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113206");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-05 12:36:33 +0200 (Tue, 05 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-27 18:15:00 +0000 (Thu, 27 Jun 2019)");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-11629", "CVE-2018-11681", "CVE-2018-11682");

  script_name("Lutron Devices Default Credentials (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Lutron devices have default admin credentials that cannot be changed.");

  script_tag(name:"vuldetect", value:"Tries to login with the default credentials and reports if it was
  successful.");

  script_tag(name:"insight", value:"The devices each use one of the two following (user:password) pairs:

  - lutron:integration

  - nwk:nwk2");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain admin access to the
  target system.");

  script_tag(name:"affected", value:"The vulnerability affects multiple Lutron devices.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://sadfud.me/explotos/CVE-2018-11629");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = telnet_get_port( default: 23 );
if( get_kb_item( "telnet/" + port + "/no_login_banner" ) )
  exit( 0 );

creds = make_array( "lutron", "integration",
                    "nwk", "nwk2" );

foreach login( keys( creds ) ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  recv = recv( socket: soc, length: 2048 );
  if( ! recv )
    continue;

  if( "login:" >< tolower( recv ) ) {
    send( socket: soc, data: login + '\r\n' );
    recv = recv( socket: soc, length: 256 );

    if( recv && "password:" >< tolower( recv ) ) {
      send( socket: soc, data: creds[login] + '\r\n' );
      recv = recv( socket: soc, length: 2048 );

      VULN = FALSE;
      if( "QNET>" >< recv)
        VULN = TRUE;

      send( socket: soc, data: '?HELP,#ETHERNET\r\n' );
      recv = recv( socket: soc, length: 2048 );

      if( "Configures the IP" >< recv || VULN ) {
        report = 'It was possible to gain administrative access using the credentials: "' + login + '":"' + creds[login] + '".';
        security_message( data: report, port: port );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

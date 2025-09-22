# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105075");
  script_version("2025-07-22T05:43:35+0000");
  script_cve_id("CVE-2025-34117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2014-09-01 12:03:46 +0200 (Mon, 01 Sep 2014)");
  script_name("Netcore/Netis Devices Backdoor Access (UDP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_default_credentials_options.nasl");
  script_require_udp_ports(53413);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://web.archive.org/web/20140828114943/http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43387");
  script_xref(name:"URL", value:"https://www.shadowserver.org/what-we-do/network-reporting/netcore-netis-router-vulnerability-scan-report/");

  script_tag(name:"impact", value:"Clients can leverage this service to execute arbitrary commands
  on the underlying system");

  script_tag(name:"vuldetect", value:"Send a special request to UDP port 53413 and check the
  response.");

  script_tag(name:"insight", value:"Affected devices include a backdoor service listening on UDP
  port 53413.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"Netcore/Netis devices are exposing a backdoor access.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

port = 53413;
if( ! get_udp_port_state( port ) ) exit( 0 );
if( ! soc = open_sock_udp( port ) ) exit( 0 );

send( socket:soc, data:'' );
recv = recv( socket:soc, length:64, timeout:3 );

if( "Login:" >!< recv ) exit( 0 );

send( socket:soc, data:'XXXXXXXXnetcore' );
recv = recv( socket:soc, length:128, timeout:3 );

close( soc );

if( "Login successed" >< recv ) {
  security_message( port:port, proto:'udp' );
  exit( 0 );
}

exit( 99 );

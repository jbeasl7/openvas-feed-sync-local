# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105023");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CS121 UPS Default Admin Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-12 11:02:06 +0200 (Mon, 12 May 2014)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("HyNetOS/banner");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote CS121 UPS web interface is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

if( "HyNetOS" >!< banner ) exit( 0 );

buf = http_get_cache(item:"/", port:port);

if( "<title>CS121" >!< buf ) exit( 0 );

req = http_get(item:'/admin/net.shtml', port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( "401 Unauthorized" >!< buf ) exit( 0 );

userpass = base64 (str:'admin:cs121-snmp');
useragent = http_get_user_agent();

req = 'GET /admin/net.shtml HTTP/1.0\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Authorization: Basic ' + userpass + '\r\n\r\n';

buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( "Security Settings" >< buf && "Gateway Address" >< buf )
{
  report = 'It was possible to login using "admin" as username and "cs121-snmp" as password.\n';

  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );

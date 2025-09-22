# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:rockmongo:rockmongo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111030");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Rockmongo Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-21 18:00:00 +0200 (Fri, 21 Aug 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("sw_rockmongo_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("rockmongo/installed");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Rockmongo web interface is using known default
  credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/admin");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

host = http_host_name( port:port );

data = string( "more=0&host=0&username=admin&password=admin&db=&lang=en_us&expire=3" );
len = strlen( data );
useragent = http_get_user_agent();
req = 'POST ' + dir + '/index.php?action=login.index HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;
res = http_keepalive_send_recv( port:port, data:req );

cookie = eregmatch( pattern:"PHPSESSID=([0-9a-z]+);", string:res );
if( isnull( cookie[1] ) )
  exit( 0 );

req = 'GET ' + dir + '/index.php?action=admin.index&host=0 HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Cookie: PHPSESSID=' + cookie[1] + '\r\n' +
      '\r\n';
res = http_keepalive_send_recv( port:port, data:req );

if( "Processlist" >< res && "Master/Slave" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

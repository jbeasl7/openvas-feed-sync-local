# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105089");
  script_version("2023-09-28T05:05:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OpenMediaVault Default Admin Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-09-28 05:05:04 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"creation_date", value:"2014-09-15 12:02:06 +0200 (Mon, 15 Sep 2014)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote OpenMediaVault web interface is using known default
  credentials.");

  script_tag(name:"vuldetect", value:"Tries to login with known default credentials via HTTP.");

  script_tag(name:"insight", value:"It was possible to login with default credentials admin/openmediavault");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
buf = http_get_cache( item:"/", port:port );

if( "<title>OpenMediaVault web administration interface" >!< buf && "<title>openmediavault Workbench" >!< buf &&
    "<title>OpenMediaVault - Web administration interface" >!< buf && "<title>openmediavault control panel" >!< buf )
  exit( 0 );

valid_services = make_list( "Authentication", "Session" );

useragent = http_get_user_agent();
host = http_host_name( port:port );
cookie = http_get_cookie_from_header( buf:buf );

# n.b validated from openmediavault 0.2 to 6.x
foreach vs( valid_services ) {
  data = '{"service":"' + vs  + '","method":"login","params":{"username":"admin","password":"openmediavault"}}';
  # n.b. Special handling for Openmediavault 0.2 which does not contain the language selection field and requires a different data structure
  # Newer versions without the language selection field (6.x) do not use Set-Cookie
  if( cookie && "LanguageComboBox" >!< buf ) {
    data = '{"service":"' + vs  + '","method":"login","params":[{"username":"admin","password":"openmediavault"}]}';
  }
  len = strlen( data );

  req = 'POST /rpc.php HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
        'Accept-Encoding: Identity\r\n' +
        'Content-Type: application/json; charset=UTF-8\r\n' +
        'X-Requested-With: XMLHttpRequest\r\n' +
        'Referer: http://' + host + '/\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Connection: close\r\n' +
        'Pragma: no-cache\r\n' +
        'Cache-Control: no-cache\r\n' +
        '\r\n' +
        data;

  bufRet = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( '"authenticated":true' >< bufRet && '"username":"admin"' >< bufRet ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105123");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Device42 DCIM Appliance Manager Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-28 12:02:06 +0200 (Fri, 28 Nov 2014)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4242);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Device42 DCIM Appliance Manager web interface
  is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: d42admin/default");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:4242 );

url = '/accounts/login/';
buf = http_get_cache( item:url, port:port );

if( "<title>Device42 Appliance Manager" >!< buf ) exit( 0 );

csrf_token = eregmatch( pattern:'csrftoken=([^; ]+)', string:buf );
if( isnull( csrf_token[1] ) ) exit( 0 );

csrf = csrf_token[1];

d42amid_token = eregmatch( pattern:'d42amid=([^; ]+)', string:buf );
if( isnull( d42amid_token[1] ) ) exit( 0 );

d42amid = d42amid_token[1];

login_data = 'csrfmiddlewaretoken=' + csrf  + '&username=d42admin&password=default&next=%2F';
len = strlen( login_data );

host = http_host_name( port:port );
useragent = http_get_user_agent();

req = 'POST /accounts/login/ HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Referer: http://' +  host + ':' + port + '/accounts/login/?next=/\r\n' +
      'Cookie: csrftoken=' + csrf  + '; d42amid=' + d42amid + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      login_data;

buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( buf !~ "HTTP/1\.. 302" || "d42amid" >!< buf ) exit( 0 );

d42amid_token1 =  eregmatch( pattern:'d42amid=([^; ]+)', string:buf );
if( isnull( d42amid_token1[1] ) ) exit( 0 );

d42amid1 = d42amid_token1[1];

req = 'GET / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Cookie: d42amid=' + d42amid1 + '\r\n' +
      '\r\n';

result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ">Change password<" >< result && ">Sign Out<" >< result )
{
  set_kb_item( name:'device42/csrf', value: csrf );
  set_kb_item( name:'device42/d42amid', value: d42amid1 );
  set_kb_item( name:'device42/port', value: port );
  security_message( port:port );
  exit( 0 );
}

exit( 99 );


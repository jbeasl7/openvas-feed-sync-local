# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:content_security_management_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105435");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cisco Content Security Management Appliance Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-11-06 14:06:55 +0100 (Fri, 06 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_csma_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco_csm/http/cookie", "cisco_csm/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Cisco Content Security Management Appliance web interface
  is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/ironport");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! cookie = get_kb_item( "cisco_csm/http/" + port + "/cookie" ) )
  exit( 0 );

postdata = "action=Login&referrer=&screen=login&username=admin&password=ironport";
len = strlen( postdata );

url = "/login";

host = http_host_name( port:port );
useragent = http_get_user_agent();

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Connection: Close\r\n' +
      'Host: ' + host + '\r\n' +
      'Pragma: no-cache\r\n' +
      'Cache-Control: no-cache\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' +
      'Accept-Language: en\r\n' +
      'Accept-Encoding: identify\r\n' +
      'Cookie: ' + cookie + '\r\n' +
      'Accept-Charset: iso-8859-1,*,utf-8\r\n' +
      'X-Requested-With: XMLHttpRequest\r\n' +
      'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      postdata;
res = http_keepalive_send_recv( port:port, data:req );

if( !res || "authenticated" >!< res )
  exit( 99 );

ac = eregmatch( pattern:"Set-Cookie: (authenticated=[^;]+;)", string:res );
if( isnull( ac[1] ) )
  exit( 0 );

cookie = ac[1] + cookie;

if( http_vuln_check( port:port, url:"/services/system_status", pattern:"action=Logout", extra_check:make_list("System Status", "Logged in as"), cookie:cookie ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

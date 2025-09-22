# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105101");
  script_cve_id("CVE-2014-3704");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-26T05:05:09+0000");

  script_name("Drupal Core SQLi Vulnerability (SA-CORE-2014-005) - Active Check");

  script_xref(name:"URL", value:"https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2014-10-15/sa-core-2014-005-drupal-core-sql");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70595");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to execute
  arbitrary code, to gain elevated privileges and to compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"vuldetect", value:"Sends a special crafted HTTP POST request and checks the
  response.");

  script_tag(name:"insight", value:"Drupal fails to sufficiently sanitize user-supplied data before
  using it in an SQL query.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Drupal is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"affected", value:"Drupal 7.x versions prior to 7.32 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-30 17:18:15 +0100 (Thu, 30 Oct 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/http/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vt_strings = get_vt_strings();
vtstring = vt_strings["default"];
useragent = http_get_user_agent();
host = http_host_name( port:port );

data = 'name[0;%20SELECT+' + vtstring + ';#]=0&name[0]==' + vtstring + '&pass=' + vtstring + '&test2=test&form_build_id=&form_id=user_login_block&op=Log+in';
len = strlen( data );

url = dir  + '/?q=node&destination=node';
req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Cookie: ZDEDebuggerPresent=php,phtml,php3\r\n' +
      'Connection: Close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "warning.*mb_strlen\(\) expects parameter 1" && "The website encountered an unexpected error" >!< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
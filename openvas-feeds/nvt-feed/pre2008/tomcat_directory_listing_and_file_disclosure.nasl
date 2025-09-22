# SPDX-FileCopyrightText: 2003 A.D.Consulting
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11438");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2003-0042", "CVE-2003-0043");
  script_name("Apache Tomcat < 3.3.1a Directory Listing and File Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 A.D.Consulting");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210420135001/http://www.securityfocus.com/bid/6721");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210413203724/http://www.securityfocus.com/bid/6722");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a directory listing and a file
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw allows remote attackers to potentially list directories
  even with an index.html or other file present, or obtain unprocessed source code for a JSP
  file.");

  script_tag(name:"affected", value:"Apache Tomcat prior to version 3.3.1a when used with JDK 1.3.1
  or earlier.");

  script_tag(name:"solution", value:"Update to version 3.3.1a or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

res = http_get_cache( item:"/", port:port );
if( ! res || "Index of /" >< res || "Directory Listing" >< res )
  exit( 0 );

req = http_get( item:"/<REPLACEME>.jsp", port:port );
req = str_replace( string:req, find:"<REPLACEME>", replace:raw_string( 0 ) );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res )
  exit( 0 );

if( "Index of /" >< res || "Directory Listing" >< res ) {
  report = http_report_vuln_url( port:port, url:"/<asciinullchar>.jsp" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

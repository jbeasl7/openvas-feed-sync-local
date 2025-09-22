# SPDX-FileCopyrightText: 2004 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12123");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-2007");
  script_name("Apache Tomcat source.jsp Malformed Request Information Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Kyger");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210208095435/http://www.securityfocus.com/bid/4876");

  script_tag(name:"summary", value:"The source.jsp file, distributed with Apache Tomcat server, will
  disclose information when passed a malformed request.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"impact", value:"As a result, information such as the web root path and directory
  listings could be obtained.

  Examples:

  http://example.com/examples/jsp/source.jsp?? - reveals the web root

  http://example.com/examples/jsp/source.jsp?/jsp/ - reveals the contents of the jsp directory");

  script_tag(name:"affected", value:"Apache Tomcat versions 3.2.3 and 3.2.4 are known to be
  affected. Other newer or older versions might be affected as well.");

  script_tag(name:"solution", value:"Remove the default files from the web server.");

  script_tag(name:"solution_type", value:"Mitigation");
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

foreach url( make_list( "/examples/jsp/source.jsp??", "/examples/jsp/source.jsp?/jsp/" ) ) {

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  if( ! buf )
    continue;

  if( "Directory Listing" >< buf && "file" >< buf ) {
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\nThe following information was obtained via a malformed request to the web server:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

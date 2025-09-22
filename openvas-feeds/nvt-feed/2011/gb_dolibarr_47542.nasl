# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103144");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr <= 3.0.0 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dolibarr/http/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to a local file include (LFI) vulnerability
  and a cross-site scripting (XSS) vulnerability because it fails to properly sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An attacker can exploit the local file include vulnerability
  using directory-traversal strings to view and execute local files within the context of the
  affected application. Information harvested may aid in further attacks.

  The attacker may leverage the cross-site scripting issues to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Dolibarr version 3.0.0 and probably prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47542");
  script_xref(name:"URL", value:"http://www.dolibarr.org/downloads/cat_view/62-stables-versions");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/document.php?lang=%22%3E%3Cscript%3Ealert%28%27vt-xss-test%27%29%3C/script%3E";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('vt-xss-test'\)</script>",
                     check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

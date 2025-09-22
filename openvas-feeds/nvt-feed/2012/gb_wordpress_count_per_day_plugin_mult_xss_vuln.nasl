# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803010");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2012-3434");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-08-28 02:46:18 +0530 (Tue, 28 Aug 2012)");
  script_name("WordPress Count per Day Plugin 'userperspan.php' Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49692");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54258");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/count-per-day/changelog");
  script_xref(name:"URL", value:"http://www.darksecurity.de/advisories/2012/SSCHADV2012-015.txt");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/571926/count-per-day#file22");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress Count per Day Plugin version 3.1.1 and prior.");

  script_tag(name:"insight", value:"The input passed via 'page', 'datemin' and 'datemax' parameters to
  '/wp-content/plugins/count-per-day/userperspan.php' script is not properly
  validated, which allows attackers to execute arbitrary HTML and script code
  in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Update to WordPress Count per Day Plugin version 3.2 or later.");

  script_tag(name:"summary", value:"The WordPress plugin 'Count per Day' is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/wp-content/plugins/count-per-day/userperspan.php?page="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"><script>alert\(document\.cookie\)</script>", extra_check:"<title>Count per Day")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

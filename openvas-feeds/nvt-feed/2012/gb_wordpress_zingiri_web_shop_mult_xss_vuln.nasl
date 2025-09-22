# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902831");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-6506");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-27 14:14:14 +0530 (Fri, 27 Apr 2012)");
  script_name("WordPress Zingiri Web Shop Plugin Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53278");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18787");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112216/WordPress-Zingiri-Web-Shop-2.4.0-Cross-Site-Scripting.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress Zingiri Web Shop Plugin Version 2.4.0 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  passed to 'page' and 'notes' parameters, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");

  script_tag(name:"solution", value:"Upgrade to WordPress Zingiri Web Shop Plugin 2.4.1 or later.");

  script_tag(name:"summary", value:"WordPress Zingiri Web Shop Plugin is prone to multiple cross site scripting vulnerabilities.");

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

url = dir + '/?page="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check:"Zingiri Web Shop")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

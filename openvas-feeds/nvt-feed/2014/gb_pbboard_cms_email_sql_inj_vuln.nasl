# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805205");
  script_version("2025-06-25T05:41:02+0000");
  script_cve_id("CVE-2014-9215");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2014-12-08 15:01:55 +0530 (Mon, 08 Dec 2014)");
  script_name("PBBoard CMS <= 3.0.1 'email' Parameter SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/35473");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122083240/http://www.securityfocus.com/bid/71471");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210116141100/http://www.securityfocus.com/archive/1/534149/30/0/threaded");
  script_xref(name:"URL", value:"http://www.itas.vn/news/ITAS-Team-discovered-SQL-Injection-in-PBBoard-CMS-68.html");

  script_tag(name:"summary", value:"PBBoard CMS is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'email' POST parameter to
  the /includes/functions.class.php script is not properly sanitized before
  returning to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to inject or manipulate SQL queries in the back-end database allowing for the
  manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"PBBoard CMS version 3.0.1 and prior.");

  script_tag(name:"solution", value:"Update to latest version 3.0.1 (updated on 28/11/2014) or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir(make_list_unique("/", "/PBBoard", "/pbb", "/forum", "/cms", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if(res && res =~ ">Powered by.*PBBoard<") {
    url = dir + "/index.php?page=register&checkemail=1";

    postData = "email='Sql-Injection-Test@f.com";

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded; charset=UTF-8", "\r\n",
                 "Referer: http://", host, dir, "/index.php?page=register&index=1&agree=1", "\r\n",
                 "Content-Length: ", strlen(postData), "\r\n\r\n",
                 postData, "\r\n");
    res = http_keepalive_send_recv(port:port, data:req);

    if(res && "You have an error in your SQL syntax" >< res && "Sql-Injection-Test" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

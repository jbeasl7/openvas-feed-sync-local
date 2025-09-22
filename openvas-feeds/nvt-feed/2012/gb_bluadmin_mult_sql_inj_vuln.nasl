# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802868");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-06-18 16:14:31 +0530 (Mon, 18 Jun 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Bluadmin Multiple SQLi Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Bluadmin is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The input passed via 'ver' parameter to 'get_imagesf.php' and
  'get_flash_info.php' is not properly sanitised before being used in SQL queries, which allows
  attackers to execute arbitrary SQL commands in the context of an affected application or site.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause SQL
  injection attack and gain sensitive information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18644");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/06/bluadmin-sql-injection.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113779/bluadmin-sql.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/bluadmin", http_cgi_dirs(port: port))) {

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/get_flash_info.php");
  if (res !~ "^HTTP/1\.[01] 200")
    continue;

  url = dir + "/get_flash_info.php?ver=1'";

  if (http_vuln_check(port: port, url: url, check_header: TRUE,
                      pattern: "mysql_fetch_array\(\): supplied argument is not a valid MySQL result",
                      extra_check: make_list("get_flash_info.php", "extract\(\)", "eval\(\)'d code"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

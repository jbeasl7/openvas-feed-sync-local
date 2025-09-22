# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805159");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2015-1471");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-04-03 11:17:18 +0530 (Fri, 03 Apr 2015)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Pragyan CMS SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Pragyan CMS is prone to an SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"Flaw is due to the userprofile.lib.php
  script not properly sanitizing user-supplied input appended to 'user:#'
  in the URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Pragyan CMS version 3.0. Prior versions
  may also be affected.");

  script_tag(name:"solution", value:"As a workaround locate the file
  userprofile.lib.php and use the patch provided in the referenced link.");

  script_xref(name:"URL", value:"http://pastebin.com/ip2gGYuS");

  script_tag(name:"solution_type", value:"Mitigation");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q1/402");
  script_xref(name:"URL", value:"https://github.com/delta/pragyan/issues/206");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/18");
  script_xref(name:"URL", value:"http://sroesemann.blogspot.de/2015/01/sroeadv-2015-11.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/pragyan", "/cms", "/pragyancms", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/home/+login", port:port);

  if(">Pragyan CMS" >< res && "Login<" >< res) {
    url = dir + "/user:1'SQL-INJECTION-TEST";

    if(http_vuln_check(port:port, url:url, check_header:FALSE, pattern:"You have an error in your SQL syntax", extra_check:"SQL-INJECTION-TEST")) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

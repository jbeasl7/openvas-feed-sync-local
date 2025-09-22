# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802977");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-5288");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-10-05 16:54:35 +0530 (Fri, 05 Oct 2012)");
  script_name("phpMyDirectory 'id' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51342");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72232");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18338/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to inject or manipulate SQL queries
  in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"phpMyDirectory version 1.3.3");

  script_tag(name:"insight", value:"Input passed via the 'id' parameter to page.php is not properly sanitised
  before being used in SQL queries.");

  script_tag(name:"solution", value:"Upgrade to phpMyDirectory version 1.4.1 or later.");

  script_tag(name:"summary", value:"phpMyDirectory is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.phpmydirectory.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/phpMyDirectory", "/phpmydirectory", "/pmd", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && '>phpMyDirectory.com<' >< res ) {

    url = dir + "/page.php?id='";

    if(http_vuln_check(port:port, url:url,check_header: TRUE, pattern:'You have an error in your SQL syntax;')) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

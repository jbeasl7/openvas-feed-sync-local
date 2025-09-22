# SPDX-FileCopyrightText: 2003 k-otik.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11445");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Basit CMS 1.0 XSS and SQLi Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2003 k-otik.com");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7139");

  script_tag(name:"summary", value:"Basit CMS is prone to a cross-site scripting (XSS) and a SQL
  injection (SQLi) vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Basit CMS has an XSS bug. An attacker may use it to perform an
  XSS attack on this host.

  In addition to this, it is vulnerable to a SQLi attack which may allow an attacker to get the
  control of the remote database.");

  script_tag(name:"affected", value:"Basit CMS version 1.0 is known to be affected. Other versions
  might be affected as well.");

  script_tag(name:"solution", value:"Update to a newer version.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(dont_add_port:TRUE);
if(http_get_has_generic_xss(port:port, host:host))
  exit(0);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(port:port, item:dir + "/modules/Submit/index.php");
  if(!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  url = dir + "/modules/Submit/index.php?op=pre&title=<script>window.alert(document.cookie);</script>";

  if(http_vuln_check(port:port, url:url, pattern:"<script>window\.alert\(document\.cookie\);</script>", check_header:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

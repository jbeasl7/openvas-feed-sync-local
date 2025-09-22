# SPDX-FileCopyrightText: 2000 John Lampe <j_lampe@bellsouth.net>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10440");
  script_version("2024-04-24T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-04-24 05:05:32 +0000 (Wed, 24 Apr 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0505", "CVE-2001-0729");
  script_name("Apache HTTP Server Multiple '/' Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_13.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121153255/http://www.securityfocus.com/bid/1284/");

  script_tag(name:"summary", value:"Certain versions of Apache HTTP Server for Win32 have a
  bug wherein remote users can list directory entries.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"Specifically, by appending multiple /'s to the HTTP GET command,
  the remote Apache server will list all files and subdirectories within the web root (as defined in
  httpd.conf).");

  script_tag(name:"solution", value:"Update to version 1.3.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function find_index(k, port) {

  if(k < 16)
    k = 17;

  for(q = k - 16; q < k; q++) {
    buf = http_get(item:crap(length:q, data:"/"), port:port);
    incoming = http_keepalive_send_recv(port:port, data:buf);
    if (!incoming)
      continue;

    if("Index of /" >< incoming)  {
      report = string(q, " slashes will cause the directory contents to be listed.");
      security_message(port:port, data:report);
      exit(0);
    }
  }
  exit(0);
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

res = http_get_cache(item:"/", port:port);
if(!res || "Index of /" >< res)
  exit(0);

for(i = 2; i < 512; i = i + 16) {
  req = http_get(item:crap(length:i, data:"/"), port:port);
  incoming = http_keepalive_send_recv(port:port, data:req);
  if(!incoming)
    continue;

  if("Forbidden" >< incoming) {
    find_index(k:i, port:port);
  }
}

exit(99);

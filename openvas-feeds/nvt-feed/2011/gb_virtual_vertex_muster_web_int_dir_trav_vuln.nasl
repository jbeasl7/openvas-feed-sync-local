# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802279");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2011-4714");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-30 13:13:13 +0530 (Wed, 30 Nov 2011)");
  script_name("Virtual Vertex Muster Web Interface Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46991");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50841");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/46991");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Muster-Arbitrary_File_Download.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8690);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");

  script_tag(name:"affected", value:"Virtual Vertex Muster version 6.1.6.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of URI containing ../(dot dot)
  sequences, which allows attackers to read arbitrary files via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade to Virtual Vertex Muster version 6.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Virtual Vertex Muster is prone to a directory traversal vulnerability.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8690);

res = http_get_cache(item:"/dologin.html", port:port);

if("<title>Muster 6 Integrated Web server" >< res) {
  url = "/a\..\..\muster.db";
  if(http_vuln_check(port:port, url:url, pattern:"SQLite format", check_header:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
}

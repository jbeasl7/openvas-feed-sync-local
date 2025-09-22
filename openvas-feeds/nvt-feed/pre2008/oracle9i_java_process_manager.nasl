# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10851");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4293");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0563");
  script_name("Oracle 9iAS Java Process Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_tag(name:"solution", value:"Restrict access to /oprocmgr-status in httpd.conf");

  script_tag(name:"summary", value:"The remote host is an Oracle 9iAS server. It is possible to
  obtain the list of Java processes running on the remote host anonymously, as well as to start
  and stop them.");

  script_tag(name:"impact", value:"By default, accessing the location /oprocmgr-status via HTTP
  lets an attacker obtain the list of processes running on the remote host, and even to start
  or stop them.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/oprocmgr-status";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(res && "Module Name" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

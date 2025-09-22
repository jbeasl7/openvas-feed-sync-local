# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:netgear:wnr2000";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809775");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-12-30 15:20:48 +0530 (Fri, 30 Dec 2016)");

  script_cve_id("CVE-2016-10175", "CVE-2016-10176", "CVE-2016-10174");

  script_tag(name:"qod_type", value:"remote_active");
  script_name("NETGEAR WNR2000 Router Multiple Vulnerabilities (Dec 2016) - Active Check");

  script_tag(name:"summary", value:"NETGEAR WNR2000 Router devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get specific information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The device leaks its serial number while requesting for
    'BRS_netgear_success.html'.

  - Improper access control while sending request to 'apply_noauth.cgi'.

  - Timestamps used in application can be easily calculated and generated outside.

  - Improper handling of access to *.cgi files by HTTP server in the device (uhttpd).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, reboot router,
  factory reset the router, change WLAN settings, change password recovery settings,
  obtain the admin password once recovery settings are changed, execute code and
  conduct denial of service attack.");

  script_tag(name:"affected", value:"NETGEAR WNR2000 routers.");

  script_tag(name:"solution", value:"NETGEAR has released beta firmware for the affected routers,
  which can be obtained from the referenced vendor KB entry.");

  script_xref(name:"URL", value:"http://kb.netgear.com/000036549/Insecure-Remote-Access-and-Command-Execution-Security-Vulnerability");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Dec/72");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/pedrib/PoC/master/advisories/netgear-wnr2000.txt");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_wnr2000_router_detect.nasl");
  script_mandatory_keys("netgear_wnr2000/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/BRS_netgear_success.html";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "wnr2000" >< res && "netgear" >< res) {
  serial = eregmatch(pattern:'var sn="([0-9A-Za-z]+)";', string:res);
  if(serial[1]) {
    report = http_report_vuln_url(port:port, url:url);
    report += '\n\nExtracted serial:\n\n' + serial[0];
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

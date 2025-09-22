# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801865");
  script_cve_id("CVE-2011-1523");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Nagios <= 3.2.3 'layer' XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagios/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46826");
  script_xref(name:"URL", value:"http://tracker.nagios.org/view.php?id=207");
  script_xref(name:"URL", value:"http://www.rul3z.de/advisories/SSCHADV2011-002.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99164/SSCHADV2011-002.txt");

  script_tag(name:"summary", value:"Nagios is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'layer' parameter to cgi-bin/statusmap.cgi, which allows attackers to execute
  arbitrary HTML and script code on the web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Nagios versions 3.2.3 and prior.");

  script_tag(name:"solution", value:"Update to version 3.3.1 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/cgi-bin/statusmap.cgi?layer=%27%20onmouseover=%22alert" +
            "(%27vt-xss-test%27)%22";

if (http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"alert\('vt-xss-test'\)")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

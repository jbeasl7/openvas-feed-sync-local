# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802261");
  script_version("2024-06-18T05:05:55+0000");
  script_tag(name:"last_modification", value:"2024-06-18 05:05:55 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XAMPP < 1.7.7 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xampp_http_detect.nasl");
  script_mandatory_keys("xampp/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"XAMPP is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied
  input to the 'text' parameter in 'ming.php' and input appended to the URL in cds.php, that allows
  attackers to execute arbitrary HTML and script code in a user's browser session in the context of
  an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"XAMPP version 1.7.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.7.7 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/106244/xampp174-xss.txt");
  script_xref(name:"URL", value:"http://mc-crew.info/xampp-1-7-4-for-windows-multiple-site-scripting-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/cds.php/'onmouseover=alert(document.cookie)>";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if (ereg(pattern:"^HTTP/1\.[01] 200", string:res) && "cds.php/'onmouseover=alert(document.cookie)>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

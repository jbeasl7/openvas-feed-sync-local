# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adiscon:log_analyzer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802645");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-06-21 11:11:11 +0530 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-3790");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adiscon LogAnalyzer < 3.4.4, 3.5.x < 3.5.5 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adiscon_log_analyzer_http_detect.nasl");
  script_mandatory_keys("adiscon/log_analyzer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Adiscon LogAnalyzer is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'highlight' parameter in index.php is not
  properly verified before it is returned to the user. This can be exploited to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Adiscon LogAnalyzer prior to version 3.4.4 and 3.5.x prior to
  3.5.5.");

  script_tag(name:"solution", value:"Update to version 3.4.4, 3.5.5 or later.");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=504");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_LogAnalyzer_XSS_Vuln.txt");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/security-advisories/loganalyzer-cross-site-scripting-vulnerability-in-highlight-parameter");

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

url = dir + '/index.php/?search=Search&highlight="<script>alert(document.cookie)</script>';

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adiscon:log_analyzer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902840");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-05-28 15:15:15 +0530 (Mon, 28 May 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adiscon LogAnalyzer < 3.4.3 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adiscon_log_analyzer_http_detect.nasl");
  script_mandatory_keys("adiscon/log_analyzer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Adiscon LogAnalyzer is prone to multiple SQL injection (SQLi)
  and cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input passed via the 'filter' parameter to index.php, the 'id' parameter to admin/reports.php
  and admin/searches.php is not properly sanitised before being returned to the user.

  - Input passed via the 'Columns[]' parameter to admin/views.php is not properly sanitised before
  being used in SQL queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal
  cookie based authentication credentials, compromise the application, access or modify data or
  exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Adiscon LogAnalyzer version 3.4.2 and prior.");

  script_tag(name:"solution", value:"Update to version 3.4.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53664");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113037/CSA-12005.txt");
  script_xref(name:"URL", value:"http://www.codseq.it/advisories/multiple_vulnerabilities_in_loganalyzer");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/news/loganalyzer-v3-4-3-v3-stable-released");

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

url = dir + "/index.php?filter=</title><script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

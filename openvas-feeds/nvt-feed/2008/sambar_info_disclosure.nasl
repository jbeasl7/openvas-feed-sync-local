# SPDX-FileCopyrightText: 2008 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80082");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2003-1284");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Sambar Information Disclosure (CVE-2003-1284) - Active Check");

  script_category(ACT_ATTACK); # nb: Direct access to a .exe file might be already seen as an attack

  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("gb_sambar_server_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"summary", value:"The remote web server is running two CGIs (environ.pl and
  testcgi.exe) which, by default, disclose a lot of information about the remote host (such as the
  physical path to the CGIs on the remote filesystem).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Delete the two aforementioned CGIs.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7208");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/cgi-bin/testcgi.exe";

if (http_vuln_check(port: port, url: url, pattern: "SCRIPT_FILENAME", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

url = "/cgi-bin/environ.pl";

if (http_vuln_check(port: port, url: url, pattern: "DOCUMENT_ROOT", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

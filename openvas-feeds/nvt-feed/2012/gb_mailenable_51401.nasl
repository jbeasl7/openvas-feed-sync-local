# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103388");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-01-13 10:03:24 +0100 (Fri, 13 Jan 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-0389");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable XSS Vulnerability (Jan 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"MailEnable is prone to a cross-site scripting (XSS)
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"The following MailEnable versions are vulnerable:

  Professional, Enterprise, and Premium 4.26 and prior versions

  Professional, Enterprise, and Premium 5.52 and prior versions

  Professional, Enterprise, and Premium 6.02 and prior versions");

  script_tag(name:"solution", value:"Please see the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51401");
  script_xref(name:"URL", value:"http://www.mailenable.com/kb/Content/Article.asp?ID=me020567");

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

url = dir + "/Mondo/lang/sys/ForgottenPassword.aspx?Username=></script><script>alert(/xss-test/)</script>";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(/xss-test/\)</script>", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:openview_performance_insight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103200");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-08-16 15:29:48 +0200 (Tue, 16 Aug 2011)");
  script_cve_id("CVE-2011-2406", "CVE-2011-2407", "CVE-2011-2410");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("HP OpenView Performance Insight Security Bypass and HTML Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_hp_performance_insight_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp/openview_performance_insight/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49096");
  script_xref(name:"URL", value:"https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&cp=1-11-15-119^1211_4000_100");
  script_xref(name:"URL", value:"http://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c02942411&ac.admitted=1312903473487.876444892.199480143");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"HP OpenView Performance Insight is prone to a security-bypass
  vulnerability and an HTML-injection vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage the HTML-injection issue to inject hostile
  HTML and script code that would run in the context of the affected site, potentially allowing the
  attacker to steal cookie-based authentication credentials or to control how the site is rendered to
  the user.

  The attacker may leverage the security-bypass issue to bypass certain security restrictions and
  perform unauthorized actions in the affected application.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/jsp/sendEmail.jsp",'">',"<script>alert('vt-xss-test')</script>");

if(http_vuln_check(port:port, url:url, pattern:"<body bgcolor=.<script>alert\('vt-xss-test'\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

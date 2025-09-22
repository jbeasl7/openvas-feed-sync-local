# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103473");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2012-2269", "CVE-2012-2270", "CVE-2012-2397", "CVE-2012-2398");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-04-19 12:17:59 +0200 (Thu, 19 Apr 2012)");
  script_name("ownCloud <= 3.0.0 Multiple Input Validation Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/http/detected");
  script_require_ports("Services/www", 443);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53145");
  script_xref(name:"URL", value:"http://www.tele-consulting.com/advisories/TC-SA-2012-01.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522397");

  script_tag(name:"summary", value:"ownCloud is prone to a URI open-redirection vulnerability,
  multiple cross-site scripting (XSS) vulnerabilities and multiple HTML-injection vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker could leverage the cross-site scripting issues to
  execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site. This may let the attacker steal cookie-based authentication credentials and launch
  other attacks.

  Attacker-supplied HTML and script code would run in the context of the affected browser,
  potentially allowing the attacker to steal cookie-based authentication credentials or control how
  the site is rendered to the user. Other attacks are also possible.

  Successful exploits may redirect a user to a potentially malicious site. This may aid in phishing
  attacks.");

  script_tag(name:"affected", value:"ownCloud 3.0.0 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the reference for more
  details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/index.php?redirect_url=1"><script>alert(/xss-test/)</script><l="';

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/xss-test/\)</script>", check_header:TRUE, extra_check:"Powered by ownCloud")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

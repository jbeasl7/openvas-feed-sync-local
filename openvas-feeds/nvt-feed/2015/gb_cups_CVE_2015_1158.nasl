# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105298");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-06-15 15:24:12 +0200 (Mon, 15 Jun 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-1158", "CVE-2015-1159");

  script_name("CUPS < 2.0.3 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("cups/http/detected");

  script_tag(name:"summary", value:"Common Unix Printing System (CUPS) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-1158: An issue with how localized strings are handled in cupsd allows a reference
  counter to over-decrement when handling certain print job request errors. As a result, an attacker
  can prematurely free an arbitrary string of global scope, creating a dangling pointer to a
  repurposed block of memory on the heap. The dangling pointer causes ACL verification to fail when
  parsing 'admin/conf' and 'admin' ACLs. The ACL handling failure results in unrestricted access to
  privileged operations, allowing an unauthenticated remote user to upload a replacement CUPS
  configuration file and mount further attacks.

  - CVE-2015-1159: A cross-site scripting bug in the CUPS templating engine allows this bug to be
  exploited when a user browses the web. In certain cases, the CGI template can echo user input to
  file rather than escaping the text first. This may be used to set up a reflected XSS attack in the
  QUERY parameter of the web interface help page. By default, many linux distributions run with the
  web interface activated, OS X has the web interface deactivated by default.");


  script_tag(name:"impact", value:"These vulnerabilities may allow a remote unauthenticated attacker
  access to privileged operations on the CUPS server and to execute arbitrary javascript in a user's
  browser.");

  script_tag(name:"affected", value:"CUPS prior to version 2.0.3");

  script_tag(name:"solution", value:"Update to version 2.0.3 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/810572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75098");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75106");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37336");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/help/?QUERY=%3Ca%20href=%22%20%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E%3C!--&SEARCH=Search";

if(http_vuln_check(port:port, url:url, pattern:"script>alert\(document\.cookie\)</script>",
                   extra_check:make_list(">Online Help", "CUPS"), check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

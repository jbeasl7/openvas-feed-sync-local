# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100388");
  script_version("2024-03-08T15:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-08 15:37:10 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-12-10 18:09:58 +0100 (Thu, 10 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2005-0548", "CVE-2005-0549");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sun Solaris AnswerBook2 <= 1.4.4 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("dwhttpd/banner");

  script_tag(name:"summary", value:"Sun Solaris AnswerBook2 is prone to multiple cross-site
  scripting (XSS) vulnerabilities. These issues arise due to insufficient sanitization of
  user-supplied data facilitating execution of arbitrary HTML and script code in a user's
  browser.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following specific issues were identified:

  - It is reported that the Search function of the application is affected by a cross-site
  scripting vulnerability.

  - The AnswerBook2 admin interface is prone to cross-site scripting attacks as well.");

  script_tag(name:"impact", value:"These issues can lead to theft of cookie based credentials and
  other attacks.");

  script_tag(name:"affected", value:"AnswerBook2 version 1.4.4 and prior.");

  script_tag(name:"solution", value:"Sun has released an advisory to address these issues. The
  vendor recommends disabling the application and referring to Sun documentation at the Sun Product
  Documentation Web site.

  Please see the referenced advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12746");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-57737-1&searchclause=%22category:security%22%20%22availability,%20security%22");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/394429");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-200305-1");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8888);

banner = http_get_remote_headers(port: port);
if (!banner || "dwhttpd" >!< banner)
  exit(0);

url = "/ab2/Help_C/@Ab2HelpSearch?scope=HELP&DwebQuery=%3Cscript%3Ealert(%27VT-XSS-Test%27)%3C/script%3E&Search=+Search+";

req = http_get(port: port, item: url);
buf = http_keepalive_send_recv(port: port, data: req);
if (!buf)
  exit(0);

if (buf =~ "^HTTP/1\.[01] 200" &&
    egrep(pattern: "<script>alert\('VT-XSS-Test'\)</script>", string: buf, icase: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

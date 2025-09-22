# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:syndeocms:syndeocms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103127");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-03-25 13:20:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("SyndeoCMS <= 2.8.02 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_syndeocms_http_detect.nasl");
  script_mandatory_keys("syndeocms/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"SyndeoCMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities and an SQL injection (SQLi) vulnerability because it fails to sufficiently
  sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, compromise the application, access or modify data, or
  exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"SyndeoCMS version 2.8.02 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/517160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/517172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/517162");

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

url = dir + "/starnet/addons/scroll_page.php?speed=--></script></head><script>alert('vt-xss-test');</script>";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\('vt-xss-test'\);</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

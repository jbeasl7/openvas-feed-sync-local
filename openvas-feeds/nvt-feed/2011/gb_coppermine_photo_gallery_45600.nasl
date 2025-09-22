# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:coppermine:coppermine_photo_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103008");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4693");
  script_name("Coppermine Photo Gallery Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("coppermine_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("coppermine_gallery/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45600");
  script_xref(name:"URL", value:"http://www.waraxe.us/advisory-79.html");

  script_tag(name:"summary", value:"Coppermine Photo Gallery is prone to multiple cross-site
  scripting (XSS) vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Coppermine Photo Gallery 1.5.10 is vulnerable. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

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

url = dir + "/help.php?base=1&h=czozMzoiPHNjcmlwdD5hbGVydCgnaGVhZGVyJyk7PC9zY3JpcHQ%2bIjs&t=czozMToiPHNjcmlwdD5hbGVydCgndGV4dCcpOzwvc2NyaXB0PiI7";

if (http_vuln_check(port: port, url: url,
                    pattern: "<script>alert\('header'\);</script></h1><script>alert\('text'\);</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

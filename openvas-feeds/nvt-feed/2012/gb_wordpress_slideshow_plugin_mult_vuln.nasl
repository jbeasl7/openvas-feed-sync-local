# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802999");
  script_version("2024-05-07T05:05:33+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2012-10-18 12:07:20 +0530 (Thu, 18 Oct 2012)");
  script_name("WordPress Slideshow Plugin <= 2.1.12 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.waraxe.us/advisory-92.html");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Oct/97");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524452/30/0/threaded");

  script_tag(name:"summary", value:"WordPress Slideshow Plugin is prone to multiple cross-site
  scripting (XSS) and full path disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"- Input passed via the 'randomId', 'slides' and 'settings'
  parameters to views/SlideshowPlugin/slideshow.php, 'settings', 'inputFields'
  parameters to views/SlideshowPluginPostType/settings.php and
  views/SlideshowPluginPostType/style-settings.php is not properly sanitised before being returned
  to the user.

  - Direct request to the multiple '.php' files reveals the full installation path.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site and to
  gain sensitive information like installation path location.");

  script_tag(name:"affected", value:"WordPress Slideshow Plugin version 2.1.12 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + '/wp-content/plugins/slideshow-jquery-image-gallery/views/SlideshowPlugin/slideshow.php?randomId="><script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\);</script>")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

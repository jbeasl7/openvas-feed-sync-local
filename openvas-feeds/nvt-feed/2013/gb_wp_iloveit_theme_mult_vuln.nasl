# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cosmothemes:iloveit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803844");
  script_version("2023-12-22T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-12-22 16:09:03 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-07-29 12:46:47 +0530 (Mon, 29 Jul 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("WordPress I Love It Theme <= 1.9 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_themes_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/iloveit/detected");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013070104");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122386/wpiloveit-xssdisclose.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-i-love-it-xss-content-spoofing-path-disclosure");

  script_tag(name:"summary", value:"The WordPress theme 'I Love It' is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input passed via 'playerID' parameter to '/iloveit/lib/php/assets/player.swf'
  is not properly sanitised before being return to the user.

  - No proper access restriction to certain files.");

  script_tag(name:"affected", value:"WordPress I Love It Theme version 1.9 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary HTML or script code in the context of the affected site and disclose some sensitive
  information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

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

url = dir + "/index.php";

if(http_vuln_check(port:port, url:url,
                   pattern:"<b>Fatal error</b>: .*index\.php")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

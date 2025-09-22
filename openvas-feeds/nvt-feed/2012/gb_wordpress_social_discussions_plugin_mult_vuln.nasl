# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803100");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-18 13:12:20 +0530 (Thu, 18 Oct 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Social Discussions Plugin Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.waraxe.us/advisory-93.html");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Oct/98");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to attackers to
  execute arbitrary PHP code and to gain sensitive information like installation path location.");

  script_tag(name:"affected", value:"WordPress Social Discussions Plugin version 6.1.1");

  script_tag(name:"insight", value:"The flaws are due to

  - Improper validation of user-supplied input to the 'HTTP_ENV_VARS' parameter
  in 'social-discussions-networkpub_ajax.php'.

  - Error in the social-discussions/social-discussions-networkpub.php,
  social-discussions/social-discussions.php and
  social-discussions/social_discussions_service_names.php, which reveals the
  full installation path of the script.");

  script_tag(name:"solution", value:"Update to version 6.1.2 or later.");

  script_tag(name:"summary", value:"WordPress Social Discussions Plugin is prone to remote file inclusion and full path disclosure vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/social-discussions");
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

url = dir + "/wp-content/plugins/social-discussions/social-discussions-networkpub.php";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<b>Fatal error</b>:  Call to undefined function .*social-discussions-networkpub\.php")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

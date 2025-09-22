# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805153");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2015-2314", "CVE-2015-2315");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-03-17 12:10:32 +0530 (Tue, 17 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("WordPress WPML Plugin < 3.1.9.1 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The WordPress plugin 'WPML' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper validation of parsed language code when a HTTP POST request containing the parameter
  'action=wp-link-ajax'.

  - Lack of access control over menu a 'menu sync' function.

  - The 'reminder popup' code intended for administrators in WPML did not check for login status or
  nonce.

  - The problem is the mixed use of mixed $_REQUEST and $_GET.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data and delete practically all content of the website - posts, pages, and menus.");

  script_tag(name:"affected", value:"WordPress WPML plugin versions prior to 3.1.9.1.");

  script_tag(name:"solution", value:"Update to version 3.1.9.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://klikki.fi/adv/wpml.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130810");
  script_xref(name:"URL", value:"http://wpml.org/2015/03/wpml-security-update-bug-and-fix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/534862/30/0/threaded");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

url = dir + '/wp-admin/admin.php?page=sitepress-multilingual-cms/menu'
          + '/languages.php&icl_action=reminder_popup&target=javascri'
          + 'pt:alert(document.cookie);//';

# nb: Extra check and Plugin confirmation is not possible
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"javascript:alert\(document\.cookie\)")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
